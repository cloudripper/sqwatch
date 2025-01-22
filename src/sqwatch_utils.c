#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <utime.h>
#include <libgen.h>
#include <sys/stat.h>
#include <limits.h>

#include "sqwatch.h"
#include "diff.h"


extern pid_t g_last_pid;
extern char **environ;

const char* get_signal_desc(int signo) {
    switch (signo) {
        case SIGFPE:  return "SIGFPE:  Floating point exception";
        case SIGILL:  return "SIGILL:  Illegal instruction";
        case SIGSEGV: return "SIGSEGV: Segmentation fault";
        case SIGBUS:  return "SIGBUS:  Bus error";
        case SIGABRT: return "SIGABRT: Aborted";
        case SIGTERM: return "SIGTERM: Terminated";
        case SIGINT:  return "SIGINT:  Interrupted";
        default:      return "Unknown signal";
    }
}

int add_watch(int inotify_fd, const char *path, int flags) {
  int wd = inotify_add_watch(inotify_fd, path, flags);
  return wd;
}

void print_event_type(struct inotify_event *event) {
  // Print without newline
  switch (event->mask) {
  case IN_MODIFY:
    printf(CYAN "Modified " RESET);
    break;
  case IN_CREATE:
    printf(CYAN "Created " RESET);
    break;
  case IN_DELETE:
    printf(CYAN "Deleted " RESET);
    break;
  case IN_MOVED_FROM:
    printf(CYAN "Moved from " RESET);
    break;
  case IN_MOVED_TO:
    printf(CYAN "Moved to " RESET);
    break;
  case IN_ATTRIB:
    printf(CYAN "Attributes " RESET);
    break;
  }
  fflush(stdout);  // Ensure partial line is displayed
}

void add_watches_recursive(int inotify_fd, const char *path, uint32_t flags, sqwatch_config *config) {
    struct stat path_stat;
    if (stat(path, &path_stat) == -1) {
        fprintf(stderr, RED "+ Failed to stat %s: %s\n" RESET, path, strerror(errno));
        return;
    }

    if (S_ISREG(path_stat.st_mode)) {
        // Regular file - add watch directly
        int wd = add_watch(inotify_fd, path, flags);
        if (wd != -1) {
            config->watch_paths[wd] = strdup(path);
            config->path_count++;
            printf(CYAN "+ Watch set for %s\n" RESET, path);
        }
    } else if (S_ISDIR(path_stat.st_mode)) {
        // Directory - enumerate and recurse
        DIR *dir = opendir(path);
        if (!dir) {
            fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET, path, strerror(errno));
            return;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            // Skip . and ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            // Construct full path
            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

            // Recurse into subdirectories and add files
            add_watches_recursive(inotify_fd, full_path, flags, config);
        }

        closedir(dir);
    }
}


void handle_events(int inotify_fd, sqwatch_config config) {
    char buffer[BUF_LEN];
    time_t last_event = 0;
    int events_since_last_run = 0;
    char event_buffer[256] = "";

    while (1) {
        ssize_t length = read(inotify_fd, buffer, BUF_LEN);
        if (length == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            perror("read");
            exit(EXIT_FAILURE);
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            time_t now = time(NULL);
            if (now - last_event >= config.debounce_t) {
                if (events_since_last_run > 0) {
                    printf(DARK_GREY "+ Debounced: [ %s ]\n" RESET, event_buffer);
                    event_buffer[0] = '\0';
                }
                events_since_last_run = 0;
            }
            
            if (event->mask) {
                char event_desc[32];
                snprintf(event_desc, sizeof(event_desc), "%s", 
                    event->mask & IN_MODIFY ? "Modified" :
                    event->mask & IN_CREATE ? "Created" :
                    event->mask & IN_DELETE ? "Deleted" :
                    event->mask & IN_MOVED_FROM ? "Moved from" :
                    event->mask & IN_MOVED_TO ? "Moved to" :
                    event->mask & IN_ATTRIB ? "Attributes" : "Unknown");

                if (now - last_event >= config.debounce_t) {
                    if (g_last_pid > 0) {
                        kill(-g_last_pid, SIGTERM);
                        waitpid(g_last_pid, NULL, 0);
                    }

                    printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, 
                           config.watch_paths[event->wd], event_desc);

                    if (config.command != NULL) {
                        g_last_pid = fork();
                        if (g_last_pid == -1) {
                            perror("fork");
                            exit(EXIT_FAILURE);
                        }

                        if (g_last_pid == 0) {
                            setpgid(0, 0);
                            setvbuf(stdout, NULL, _IONBF, 0);
                            setvbuf(stderr, NULL, _IONBF, 0);
                            char *const args[] = {"/bin/sh", "-c", (char *)config.command, NULL};
                            execve("/bin/sh", args, environ);
                            perror("execve");
                            exit(EXIT_FAILURE);
                        }

                        int status;
                        waitpid(g_last_pid, &status, 0);
                        if (WIFSIGNALED(status)) {
                            int sig = WTERMSIG(status);
                            fprintf(stderr, RED "+ Command terminated by signal %d (%s)\n" RESET, 
                                    sig, get_signal_desc(sig));
                        }
                    }
                    
                    if (cache_dir && config.log_file && config.verbose) {
                        if (event->mask & IN_MODIFY) {
                            char event_desc[256];
                            snprintf(event_desc, sizeof(event_desc), "Modified");
                            
                            run_diff(config.watch_paths[event->wd], 
                                cache_dir,
                                event_desc,
                                config.verbose,
                                config.log_file);
                        }
                    }

                    last_event = now;
                } else {
                    if (event_buffer[0] != '\0') {
                        strncat(event_buffer, ", ", sizeof(event_buffer) - strlen(event_buffer) - 1);
                    }
                    strncat(event_buffer, event_desc, sizeof(event_buffer) - strlen(event_buffer) - 1);
                    events_since_last_run++;
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }
}

void print_usage(void) {
  printf("Usage: sqwatch [-d directory] [-f file] [-t debounce time] -q event -c command [-l cache_dir]\n");
  printf("Options:\n");
  printf("  -d directory      Directory to watch\n");
  printf("  -f file           File to watch\n");
  printf("  -q event          Event type to watch\n");
  printf("                     all: all events\n");
  printf("                     modify: file modifications\n");
  printf("                     create: file creation\n");
  printf("                     delete: file deletion\n");
  printf("                     move: file moves\n");
  printf("                     attrib: attribute changes\n");
  printf("  -t debounce time  (Optional) Time (in seconds) after trigger to ignore events\n");
  printf("  -c command        (Optional) Command to execute when events are detected\n");
  printf("  -l log_file       (Optional) Log file to write changes to\n");
  printf("  -v verbose        (Optional) Enable verbose/diff output\n");
  printf("  -h                Display this help message\n");
}
