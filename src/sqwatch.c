#include "cache.h"
#include "diff.h"
#include "sqwatch.h"
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

pid_t g_last_pid = 0;
char *cache_dir = NULL;
sqwatch_config config;
int inotify_fd;
static const int INITIAL_DIR_WATCHES = 16;

static void cleanup(int signo) {
  printf(RED "\n+ Exiting SQWatch... \n" RESET);

  if (g_last_pid > 0) {
    kill(-g_last_pid, signo);
    waitpid(g_last_pid, NULL, 0);
  }

  // Wipe the cache directory if it exists
  if (cache_dir) {
    printf(RED "+ Wiping cache directory: %s\n" RESET, cache_dir);
    remove_directory(cache_dir);
  }

  if (inotify_fd > 0) {
    printf(RED "+ Removing watches\n" RESET);
    // Clean up file watches
    for (int i = 0; i < MAX_PATHS; i++) {
      if (config.watch_paths[i]) {
        inotify_rm_watch(inotify_fd, i);
        free(config.watch_paths[i]);
        config.watch_paths[i] = NULL;
      }
    }

    // Clean up directory watches
    for (int i = 0; i < config.dir_watch_count; i++) {
      if (config.dir_watches[i].path) {
        inotify_rm_watch(inotify_fd, config.dir_watches[i].wd);
        free(config.dir_watches[i].path);
      }
    }
    free(config.dir_watches);
    
    close(inotify_fd);
  }

  free(cache_dir);
  exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
  signal(SIGTERM, cleanup);
  signal(SIGINT, cleanup);
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

  // Determine the default cache directory
  inotify_fd = inotify_init();
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
        const char *xdg_cache_home = getenv("XDG_CACHE_HOME");
        if (!xdg_cache_home) {
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

  if (log_file) {
    printf(DARK_GREY "+ Logging to %s\n" RESET, log_file);
  }

  config.debounce_t = debounce_t;
  config.verbose = verbose;
  config.log_file = log_file;
  config.command = command;
  config.flags = flags;

  for (int i = 0; i < path_count; i++) {
    add_watches_recursive(inotify_fd, paths[i], flags, &config);
  }

  if (cache_dir && config.diff_enabled) {
    create_caches(MAX_PATHS, cache_dir, config.watch_paths, config.cached_paths, verbose);
  }

  handle_events(inotify_fd, config);
  cleanup(SIGTERM);

  return EXIT_SUCCESS;
}
