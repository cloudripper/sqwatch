#include "cache.h"
#include "diff.h"
#include "sqwatch.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

pid_t g_last_pid = 0;
char *cache_dir = NULL;
sqwatch_config config;
static const int INITIAL_DIR_WATCHES = 16;
// SIGINT and SIGTERM are read from here; see main()
static int signal_fd = -1;

// Runs once SIGINT or SIGTERM has been read from signal_fd, outside any signal
// handler. The cache goes first, as the command may take its time to exit or
// ignore signo; another signal, or 5 s, and it is killed
static void cleanup(int signo) {
  printf(RED "\n+ Exiting SQWatch... \n" RESET);

  // Wipe the cache directory if it exists
  if (cache_dir && cache_dir_owned) {
    printf(RED "+ Wiping cache directory: %s\n" RESET, cache_dir);
    remove_caches();
  }

  // Wait while anything is left in the command's process group, not only its
  // leader: a shell may exit on the signal and leave its background jobs. A
  // zombie still counts as a member; sqwatch is a subreaper (see main()), so
  // the members it orphaned are its own children and are reaped here
  if (g_last_pid > 0) {
    kill(-g_last_pid, signo);
    for (int waited = 0;; waited += 100) {
      while (waitpid(-g_last_pid, NULL, WNOHANG) > 0) {
      }
      if (kill(-g_last_pid, 0) != 0) {
        break;
      }
      struct pollfd again = {signal_fd, POLLIN, 0};
      if (waited >= 5000 || poll(&again, 1, 100) > 0) {
        killpg(g_last_pid, SIGKILL);
        while (waitpid(-g_last_pid, NULL, 0) > 0) {
        }
        break;
      }
    }
  }

  free(cache_dir);
  exit(EXIT_SUCCESS);
}

// Leave through cleanup() if SIGINT or SIGTERM is waiting. Long work outside
// the event loop calls this, so that a signal does not wait for it to finish
void stop_if_signalled(void) {
  struct pollfd pending = {signal_fd, POLLIN, 0};
  struct signalfd_siginfo info;
  if (signal_fd >= 0 && poll(&pending, 1, 0) > 0 &&
      read(signal_fd, &info, sizeof(info)) == (ssize_t)sizeof(info)) {
    cleanup((int)info.ssi_signo);
  }
}

int main(int argc, char *argv[]) {
  // SIGINT and SIGTERM stay blocked and are read from a signalfd by
  // handle_events(), so the cache is removed here, and a second signal cannot
  // interrupt that
  sigset_t stop_signals;
  sigemptyset(&stop_signals);
  sigaddset(&stop_signals, SIGINT);
  sigaddset(&stop_signals, SIGTERM);
  sigprocmask(SIG_BLOCK, &stop_signals, NULL);
  signal_fd = signalfd(-1, &stop_signals, SFD_CLOEXEC);
  if (signal_fd == -1) {
    perror("signalfd");
    exit(EXIT_FAILURE);
  }
  // Processes the command leaves behind when its shell exits become children
  // of sqwatch rather than of init, so cleanup() and stop_command() can reap
  // them and know when the command's process group is really empty
  prctl(PR_SET_CHILD_SUBREAPER, 1);
  char *command = NULL;
  char *paths[MAX_PATHS];
  int path_count = 0;
  int opt;
  uint32_t debounce_t = 1;
  char *log_file = NULL;
  int verbose = 0;

  int inotify_fd = -1;
  for (int i = 0; i < MAX_PATHS; i++) {
    config.watch_paths[i] = NULL;
    config.cached_paths[i] = NULL;
  }

  // Initialize directory watch structures
  config.dir_watches = malloc(INITIAL_DIR_WATCHES * sizeof(dir_watch));
  if (!config.dir_watches) {
    fprintf(stderr, "Failed to allocate memory for directory watches\n");
    return 1;
  }
  config.dir_watch_count = 0;
  config.max_dir_watches = INITIAL_DIR_WATCHES;
  config.root_count = 0;

  // Determine the default cache directory
  inotify_fd = inotify_init1(IN_CLOEXEC);
  if (inotify_fd == -1) {
    perror("inotify_init");
    free(config.dir_watches);  // Clean up if initialization fails
    exit(EXIT_FAILURE);
  }
  int flags = IN_MODIFY;

  static struct option long_options[] = {
    {"diff", no_argument, 0, 'D'},
    {0, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "d:f:t:q:c:l:vh", long_options, NULL)) != -1) {
    switch (opt) {
    case 'd':
      if (path_count >= MAX_PATHS) {
        fprintf(stderr, "Too many paths specified. Maximum is %d\n", MAX_PATHS);
        exit(EXIT_FAILURE);
      }
      paths[path_count++] = optarg;

      // Check if the specified path is a directory
      {
        struct stat statbuf;
        if (stat(optarg, &statbuf) != 0 || !S_ISDIR(statbuf.st_mode)) {
          fprintf(stderr, "Error: %s is not a valid directory.\n", optarg);
          exit(EXIT_FAILURE);
        }
      }
      break;
    case 'f':
      if (path_count >= MAX_PATHS) {
        fprintf(stderr, "Too many paths specified. Maximum is %d\n", MAX_PATHS);
        exit(EXIT_FAILURE);
      }
      paths[path_count++] = optarg;

      // Check if the specified path is a file
      {
        struct stat statbuf;
        if (stat(optarg, &statbuf) != 0 || !S_ISREG(statbuf.st_mode)) {
          fprintf(stderr, "Error: %s is not a valid file.\n", optarg);
          exit(EXIT_FAILURE);
        }
      }
      break;
    case 'c':
      if (optarg && strlen(optarg) > 0) {
        command = optarg;
      }
      break;
    case 't':
      debounce_t = atoi(optarg);
      printf(DARK_GREY "+ Debounce set to %d\n" RESET, debounce_t);
      break;
    case 'q':
      if (strcmp(optarg, "all") == 0) {
        flags = IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE | IN_ATTRIB | IN_CLOSE_WRITE;
        printf(GREEN "+ Monitoring all events enabled\n" RESET);
      } else if (strcmp(optarg, "modify") == 0) {
        flags = IN_MODIFY | IN_CLOSE_WRITE;
        printf(GREEN "+ Monitoring modify event enabled\n" RESET);
      } else if (strcmp(optarg, "create") == 0) {
        flags = IN_CREATE;
        printf(GREEN "+ Monitoring create event enabled\n" RESET);
      } else if (strcmp(optarg, "delete") == 0) {
        flags = IN_DELETE;
        printf(GREEN "+ Monitoring delete event enabled\n" RESET);
      } else if (strcmp(optarg, "move") == 0) {
        flags = IN_MOVE;
        printf(GREEN "+ Monitoring move event enabled\n" RESET);
      } else if (strcmp(optarg, "attrib") == 0) {
        flags = IN_ATTRIB;
        printf(GREEN "+ Monitoring attribute events enabled\n" RESET);
      } else {
        fprintf(stderr, "Invalid query option: %s\n", optarg);
        print_usage();
        exit(EXIT_FAILURE);
      }
      break;
    case 'l':
      if (optarg && strlen(optarg) > 0) {
        log_file = optarg; // log file/directory
      }

      break;
    case 'D':
      config.diff_enabled = 1;
      printf(DARK_GREY "+ Diff mode enabled\n" RESET);
      // Check for SQWATCH_CACHE_DIR environment variable
      const char *sqwatch_cache_dir = getenv("SQWATCH_CACHE_DIR");
      if (sqwatch_cache_dir) {
        if (asprintf(&cache_dir, "%s", sqwatch_cache_dir) < 0) {
          perror("Failed to allocate memory for cache_dir");
          exit(EXIT_FAILURE);
        }
        printf(DARK_GREY "+ Cache set. Using SQWATCH_CACHE_DIR: %s\n" RESET,
               cache_dir);
      } else {
        // The XDG spec says to ignore an empty or relative XDG_CACHE_HOME
        const char *xdg_cache_home = getenv("XDG_CACHE_HOME");
        if (!xdg_cache_home || xdg_cache_home[0] != '/') {
          xdg_cache_home = getenv("HOME");
          if (xdg_cache_home) {
            if (asprintf(&cache_dir, "%s/.cache/sqwatch", xdg_cache_home) < 0) {
              perror("Failed to allocate memory for cache_dir");
              exit(EXIT_FAILURE);
            }
            printf(
                DARK_GREY
                "+ Cache set. Using XDG_CACHE_HOME: %s/.cache/sqwatch\n" RESET,
                xdg_cache_home);
          }
        } else {
          if (asprintf(&cache_dir, "%s/sqwatch", xdg_cache_home) < 0) {
            perror("Failed to allocate memory for cache_dir");
            exit(EXIT_FAILURE);
          }
          printf(DARK_GREY
                 "+ Cache set.Using default cache directory: %s\n" RESET,
                 cache_dir);
        }
      }
      break;
    case 'v':
      verbose = 1;
      break;
    case 'h':
      print_usage();
      exit(EXIT_SUCCESS);
    default:
      print_usage();
      exit(EXIT_FAILURE);
    }
  }

  if (path_count == 0) {
    fprintf(stderr, "No paths specified\n");
    print_usage();
    exit(EXIT_FAILURE);
  }

  // The log is only written by diffs. It is opened here, once; a log that
  // cannot be used safely ends the run
  if (log_file && config.diff_enabled) {
    if (open_log_file(log_file) != 0) {
      exit(EXIT_FAILURE);
    }
    char shown[PATH_MAX];
    printf(DARK_GREY "+ Logging to %s\n" RESET, printable(log_file, shown, sizeof(shown)));
  }

  config.debounce_t = debounce_t;
  config.verbose = verbose;
  config.log_file = log_file;
  config.command = command;
  config.flags = flags;

  // Watches are set and files are read through /proc/self/fd/N so that they
  // act on an already opened descriptor instead of resolving a path again
  int proc_fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
  if (proc_fd == -1) {
    fprintf(stderr, "Error: cannot open /proc/self/fd (%s). sqwatch needs /proc to be mounted.\n", strerror(errno));
    exit(EXIT_FAILURE);
  }
  close(proc_fd);

  for (int i = 0; i < path_count; i++) {
    add_watches_recursive(inotify_fd, paths[i], flags, &config);
  }

  if (cache_dir && config.diff_enabled) {
    if (create_caches(cache_dir) == 0) {
      cache_watched_files(&config);
    } else {
      // Diffs would read and write files under that path: do not diff at all
      config.diff_enabled = 0;
      fprintf(stderr, RED "+ Diff disabled: cache directory %s cannot be used\n" RESET, cache_dir);
    }
  }

  cleanup(handle_events(inotify_fd, signal_fd, config));

  return EXIT_SUCCESS;
}
