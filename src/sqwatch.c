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
// SIGINT and SIGTERM are read from here; see main()
static int signal_fd = -1;

// Runs once SIGINT, SIGTERM or SIGHUP has been read from signal_fd, outside
// any signal handler, or once stdout is found closed (see
// stop_if_output_closed()). The cache goes first, as the command may take its
// time to exit or ignore signo; another signal, or 5 s, and it is killed
static void cleanup(int signo) {
  printf(RED "\n+ Exiting SQWatch... \n" RESET);

  // Remove this run's cache entries, and the cache directory if this run
  // made it
  if (cache_dir && cache_dir_fd >= 0) {
    if (cache_dir_owned) {
      printf(RED "+ Wiping cache directory: %s\n" RESET, shown_name(cache_dir));
    } else {
      printf(RED "+ Removing this run's cache entries from %s\n" RESET, shown_name(cache_dir));
    }
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

// Whether what reads stdout went away (a pipe into `head`, say): a write
// there failed with EPIPE, as SIGPIPE is ignored, or the pipe reports an
// error. revents is what poll() returned for stdout, if the caller polled it
static int output_closed(short revents) {
  return (revents & (POLLERR | POLLHUP)) || (fflush(stdout) == EOF && errno == EPIPE);
}

// Leave through cleanup() if stdout is closed, so that sqwatch is not left
// to be killed by a write with the cache behind
void stop_if_output_closed(void) {
  struct pollfd out = {STDOUT_FILENO, 0, 0};
  if (output_closed(poll(&out, 1, 0) > 0 ? out.revents : 0)) {
    cleanup(SIGTERM);
  }
}

// Leave through cleanup() if SIGINT, SIGTERM or SIGHUP is waiting, or stdout
// is closed. Long work outside the event loop calls this, so that a signal
// does not wait for it to finish
void stop_if_signalled(void) {
  struct pollfd pending[2] = {{signal_fd, POLLIN, 0}, {STDOUT_FILENO, 0, 0}};
  struct signalfd_siginfo info;
  if (signal_fd >= 0 && poll(pending, 2, 0) > 0) {
    if ((pending[0].revents & POLLIN) &&
        read(signal_fd, &info, sizeof(info)) == (ssize_t)sizeof(info)) {
      cleanup((int)info.ssi_signo);
    }
    if (output_closed(pending[1].revents)) {
      cleanup(SIGTERM);
    }
  }
}

// The values each option takes, shown after an error in its value
static const char *option_help(int opt) {
  switch (opt) {
  case 'd': return "-d DIR: an existing directory, watched with everything beneath it";
  case 'f': return "-f FILE: an existing regular file";
  case 'c': return "-c COMMAND: a shell command, run with /bin/sh -c";
  case 't': return "-t SECONDS: a decimal number of seconds from 0 to 86400, for example 1 or 0.25";
  case 'q': return "-q EVENTS: one or more of modify, create, delete, move, attrib, all,\n"
                   "  separated by commas, for example -q modify,create";
  case 'l': return "-l FILE: the log file for diffs (with --diff)";
  case 'i': return "-i PATTERN: a shell pattern (see fnmatch(3)); with a '/' it is matched\n"
                   "  against the path below the watched directory, else against the name";
  default: return NULL;
  }
}

// The value of option opt is not valid: say why and what it takes, and exit
static void bad_value(int opt, const char *value, const char *problem) {
  fprintf(stderr, "sqwatch: -%c '%s': %s\n", opt, shown_name(value), problem);
  if (option_help(opt)) {
    fprintf(stderr, "%s\n", option_help(opt));
  }
  exit(EXIT_FAILURE);
}

static void missing_argument(int opt) {
  fprintf(stderr, "sqwatch: -%c needs a value\n", opt);
  if (option_help(opt)) {
    fprintf(stderr, "%s\n", option_help(opt));
  }
  fprintf(stderr, "see sqwatch -h\n");
  exit(EXIT_FAILURE);
}

static void unknown_option(int opt, const char *arg) {
  if (opt) {
    char text[2] = {(char)opt, '\0'};
    fprintf(stderr, "sqwatch: unknown option -%s\n", shown_name(text));
  } else {
    fprintf(stderr, "sqwatch: unknown option %s\n", shown_name(arg));
  }
  fprintf(stderr, "see sqwatch -h\n");
  exit(EXIT_FAILURE);
}

// Parse a decimal number of seconds, such as 2, 0.25 or .5, into *ms, rounded
// to the nearest millisecond. Signs, exponents, hex, inf and nan are not
// numbers here, and nothing over a day is taken. Returns 0, or -1
static int parse_seconds(const char *text, long long *ms) {
  long long whole = 0, frac = 0;
  int digits = 0, places = 0, round_up = 0;
  const char *p = text;
  while (*p >= '0' && *p <= '9') {
    whole = whole * 10 + (*p++ - '0');
    digits++;
    if (whole > 86400) {
      return -1;
    }
  }
  if (*p == '.') {
    for (p++; *p >= '0' && *p <= '9'; p++, digits++) {
      if (places < 3) {
        frac = frac * 10 + (*p - '0');
        places++;
      } else if (places++ == 3) {
        round_up = *p >= '5';
      }
    }
  }
  if (!digits || *p != '\0') {
    return -1;
  }
  while (places < 3) {
    frac *= 10;
    places++;
  }
  long long value = whole * 1000 + frac + round_up;
  if (value > 86400LL * 1000) {
    return -1;
  }
  *ms = value;
  return 0;
}

// A number of milliseconds as seconds, without trailing zeros: 1, 0.25
static const char *format_seconds(long long ms) {
  static char text[32];
  int len = snprintf(text, sizeof(text), "%lld.%03lld", ms / 1000, ms % 1000);
  while (len > 0 && text[len - 1] == '0') {
    text[--len] = '\0';
  }
  if (len > 0 && text[len - 1] == '.') {
    text[--len] = '\0';
  }
  return text;
}

// The inotify events of a -q list: names separated by commas. Returns 0 and
// sets *problem if a name is not known or the list is empty
static uint32_t parse_events(const char *list, const char **problem) {
  static const struct {
    const char *name;
    uint32_t mask;
  } names[] = {
    {"modify", IN_MODIFY | IN_CLOSE_WRITE},
    {"create", IN_CREATE},
    {"delete", IN_DELETE},
    {"move", IN_MOVE},
    {"attrib", IN_ATTRIB},
    {"all", IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE | IN_ATTRIB | IN_CLOSE_WRITE},
  };
  static char why[64];
  uint32_t mask = 0;
  const char *p = list;
  while (1) {
    size_t len = strcspn(p, ",");
    size_t n = 0;
    while (n < sizeof(names) / sizeof(names[0]) &&
           (strlen(names[n].name) != len || strncmp(names[n].name, p, len) != 0)) {
      n++;
    }
    if (n == sizeof(names) / sizeof(names[0])) {
      if (len == 0) {
        *problem = "an empty event name";
      } else {
        snprintf(why, sizeof(why), "'%.*s' is not an event", len > 32 ? 32 : (int)len, p);
        *problem = shown_name(why);
      }
      return 0;
    }
    mask |= names[n].mask;
    if (p[len] == '\0') {
      return mask;
    }
    p += len + 1;
  }
}

// Say which events are watched
static void announce_events(uint32_t flags) {
  static const struct {
    const char *name;
    uint32_t mask;
  } names[] = {
    {"modify", IN_MODIFY}, {"create", IN_CREATE}, {"delete", IN_DELETE},
    {"move", IN_MOVE}, {"attrib", IN_ATTRIB},
  };
  printf(GREEN "+ Monitoring events:");
  for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
    if (flags & names[n].mask) {
      printf(" %s", names[n].name);
    }
  }
  printf("\n" RESET);
}

int main(int argc, char *argv[]) {
  // SIGINT, SIGTERM and SIGHUP (the terminal closed) stay blocked and are
  // read from a signalfd by handle_events(), so the cache is removed here,
  // and a second signal cannot interrupt that. SIGPIPE is ignored: a closed
  // stdout is seen as EPIPE, and sqwatch leaves through cleanup() then too
  sigset_t stop_signals;
  sigemptyset(&stop_signals);
  sigaddset(&stop_signals, SIGINT);
  sigaddset(&stop_signals, SIGTERM);
  sigaddset(&stop_signals, SIGHUP);
  signal(SIGPIPE, SIG_IGN);
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
  // Every -d and -f, each of them one argument at least
  char **paths = calloc(argc, sizeof(*paths));
  int path_count = 0;
  int opt;
  long long debounce_ms = 1000;
  char *log_file = NULL;
  int verbose = 0;
  uint32_t flags = 0;

  int inotify_fd = -1;
  config.roots = calloc(argc, sizeof(*config.roots));
  if (!paths || !config.roots) {
    fprintf(stderr, "Failed to allocate memory for the watched paths\n");
    return 1;
  }
  config.root_count = 0;

  inotify_fd = inotify_init1(IN_CLOEXEC);
  if (inotify_fd == -1) {
    perror("inotify_init");
    exit(EXIT_FAILURE);
  }

  static struct option long_options[] = {
    {"diff", no_argument, 0, 'D'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };

  // Errors are reported here, not by getopt: a leading ':' tells a missing
  // argument from an unknown option
  opterr = 0;
  while ((opt = getopt_long(argc, argv, ":d:f:t:q:c:l:i:wvh", long_options, NULL)) != -1) {
    struct stat statbuf;
    switch (opt) {
    case 'd':
      if (stat(optarg, &statbuf) != 0) {
        bad_value('d', optarg, strerror(errno));
      } else if (!S_ISDIR(statbuf.st_mode)) {
        bad_value('d', optarg, "not a directory");
      }
      paths[path_count++] = optarg;
      break;
    case 'f':
      if (stat(optarg, &statbuf) != 0) {
        bad_value('f', optarg, strerror(errno));
      } else if (!S_ISREG(statbuf.st_mode)) {
        bad_value('f', optarg, S_ISDIR(statbuf.st_mode) ? "a directory, not a file (use -d)" :
                                                          "not a regular file");
      }
      paths[path_count++] = optarg;
      break;
    case 'c':
      if (optarg[0] == '\0') {
        bad_value('c', optarg, "the command is empty");
      }
      command = optarg;
      break;
    case 't':
      if (parse_seconds(optarg, &debounce_ms) != 0) {
        bad_value('t', optarg, "not a number of seconds");
      }
      config.debounce_set = 1;
      break;
    case 'q': {
      const char *problem = NULL;
      uint32_t asked = parse_events(optarg, &problem);
      if (!asked) {
        bad_value('q', optarg, problem);
      }
      flags |= asked;
      break;
    }
    case 'i': {
      // A trailing '/' says nothing more: directories are matched anyway
      size_t len = strlen(optarg);
      while (len > 1 && optarg[len - 1] == '/') {
        optarg[--len] = '\0';
      }
      if (len == 0 || strcmp(optarg, "/") == 0) {
        bad_value('i', optarg, "the pattern is empty");
      }
      config.ignores = config.ignores ? config.ignores : calloc(argc, sizeof(*config.ignores));
      if (!config.ignores) {
        perror("calloc");
        exit(EXIT_FAILURE);
      }
      config.ignores[config.ignore_count++] = optarg;
      break;
    }
    case 'l':
      if (optarg[0] == '\0') {
        bad_value('l', optarg, "the path is empty");
      }
      log_file = optarg; // log file/directory
      break;
    case 'D':
      config.diff_enabled = 1;
      break;
    case 'w':
      config.wait = 1;
      break;
    case 'v':
      verbose = 1;
      break;
    case 'h':
      print_usage();
      exit(EXIT_SUCCESS);
    case ':':
      missing_argument(optopt);
      break;
    default:
      unknown_option(optopt, argv[optind - 1]);
      break;
    }
  }

  if (optind < argc) {
    fprintf(stderr, "sqwatch: unexpected argument '%s': paths to watch go after -d or -f\n"
                    "see sqwatch -h\n", shown_name(argv[optind]));
    exit(EXIT_FAILURE);
  }
  if (path_count == 0) {
    fprintf(stderr, "sqwatch: nothing to watch: give -d DIR or -f FILE\nsee sqwatch -h\n");
    exit(EXIT_FAILURE);
  }
  if (log_file && !config.diff_enabled) {
    fprintf(stderr, "sqwatch: -l needs --diff: the log holds the diffs\nsee sqwatch -h\n");
    exit(EXIT_FAILURE);
  }
  if (!flags) {
    flags = IN_MODIFY | IN_CLOSE_WRITE;  // -q modify
  }
  announce_events(flags);
  if (config.debounce_set) {
    printf(DARK_GREY "+ Debounce set to %s s\n" RESET, format_seconds(debounce_ms));
  }

  if (config.diff_enabled) {
    printf(DARK_GREY "+ Diff mode enabled\n" RESET);
    // Check for SQWATCH_CACHE_DIR environment variable
    const char *sqwatch_cache_dir = getenv("SQWATCH_CACHE_DIR");
    if (sqwatch_cache_dir) {
      if (asprintf(&cache_dir, "%s", sqwatch_cache_dir) < 0) {
        perror("Failed to allocate memory for cache_dir");
        exit(EXIT_FAILURE);
      }
      printf(DARK_GREY "+ Cache set. Using SQWATCH_CACHE_DIR: %s\n" RESET,
             shown_name(cache_dir));
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
              shown_name(xdg_cache_home));
        }
      } else {
        if (asprintf(&cache_dir, "%s/sqwatch", xdg_cache_home) < 0) {
          perror("Failed to allocate memory for cache_dir");
          exit(EXIT_FAILURE);
        }
        printf(DARK_GREY
               "+ Cache set.Using default cache directory: %s\n" RESET,
               shown_name(cache_dir));
      }
    }
  }

  // The log is only written by diffs. It is opened here, once; a log that
  // cannot be used safely ends the run
  if (log_file) {
    if (open_log_file(log_file) != 0) {
      exit(EXIT_FAILURE);
    }
    printf(DARK_GREY "+ Logging to %s\n" RESET, shown_name(log_file));
  }

  config.debounce_ms = debounce_ms;
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

  // The cache is set up before the walk, so that the walk knows it, and
  // leaves it out if it is in a watched tree
  if (cache_dir && config.diff_enabled && create_caches(cache_dir) != 0) {
    // Diffs would read and write files under that path: do not diff at all
    config.diff_enabled = 0;
    fprintf(stderr, RED "+ Diff disabled: cache directory %s cannot be used\n" RESET, shown_name(cache_dir));
  }

  for (int i = 0; i < path_count; i++) {
    add_watches_recursive(inotify_fd, paths[i], flags, &config);
  }

  if (cache_dir && config.diff_enabled) {
    cache_watched_files(&config);
  }

  cleanup(handle_events(inotify_fd, signal_fd, &config));

  return EXIT_SUCCESS;
}
