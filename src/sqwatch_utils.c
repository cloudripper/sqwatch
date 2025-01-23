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
  case IN_CLOSE_WRITE:
    printf(CYAN "Close write " RESET);
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

    if (S_ISDIR(path_stat.st_mode)) {
        // Add directory watch separately from file watches
        int wd = add_watch(inotify_fd, path, flags | IN_CREATE);
        if (wd != -1) {
            // Add to directory watches
            if (config->dir_watch_count >= config->max_dir_watches) {
                int new_size = config->max_dir_watches * 2;
                dir_watch *new_watches = realloc(config->dir_watches, 
                                               new_size * sizeof(dir_watch));
                if (!new_watches) {
                    fprintf(stderr, RED "+ Failed to allocate memory for dir watches\n" RESET);
                    return;
                }
                config->dir_watches = new_watches;
                config->max_dir_watches = new_size;
            }
            
            config->dir_watches[config->dir_watch_count].path = strdup(path);
            config->dir_watches[config->dir_watch_count].wd = wd;
            config->dir_watch_count++;
            
            if (config->verbose) {
                printf(CYAN "+ Watch set for directory %s\n" RESET, path);
            }
        }

        // Recurse into directory contents
        DIR *dir = opendir(path);
        if (!dir) {
            fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET, path, strerror(errno));
            return;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
            add_watches_recursive(inotify_fd, full_path, flags, config);
        }
        closedir(dir);
    } else if (S_ISREG(path_stat.st_mode)) {
        // Regular file handling remains unchanged
        int wd = add_watch(inotify_fd, path, flags);
        if (wd != -1 && wd < MAX_PATHS) {
            config->watch_paths[wd] = strdup(path);
            config->path_count++;
            if (config->verbose) {
                printf(CYAN "+ Watch set for file %s\n" RESET, path);
            }
        }
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
            perror("inotify read");
            exit(EXIT_FAILURE);
        }

        time_t now = time(NULL);  // Add time_t now declaration
        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            // Check if this is a directory watch event
            int is_dir_watch = 0;
            char *dir_path = NULL;
            for (int d = 0; d < config.dir_watch_count; d++) {
                if (config.dir_watches[d].wd == event->wd) {
                    is_dir_watch = 1;
                    dir_path = config.dir_watches[d].path;
                    break;
                }
            }

            if (is_dir_watch && (event->mask & IN_CREATE)) {
                char full_path[PATH_MAX];
                snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, event->name);
                
                struct stat path_stat;
                if (stat(full_path, &path_stat) == 0) {
                    if (S_ISREG(path_stat.st_mode)) {
                        // New file created - add watch
                        int new_wd = add_watch(inotify_fd, full_path, config.flags);
                        if (new_wd != -1 && new_wd < MAX_PATHS) {
                            // Free any existing path at this watch descriptor
                            if (config.watch_paths[new_wd]) {
                                free(config.watch_paths[new_wd]);
                            }
                            config.watch_paths[new_wd] = strdup(full_path);
                            
                            // Free any existing cache path before creating new one
                            if (config.cached_paths[new_wd]) {
                                free(config.cached_paths[new_wd]);
                                config.cached_paths[new_wd] = NULL;
                            }
                            
                            if (config.diff_enabled && cache_dir) {
                                create_cache_for_file(full_path, cache_dir, &config.cached_paths[new_wd], config.verbose);
                            }
                            
                            if (config.verbose) {
                                printf(CYAN "+ Added watch for new file: %s\n" RESET, full_path);
                            }
                        }
                    } else if (S_ISDIR(path_stat.st_mode)) {
                        // New directory created - add recursive watches
                        add_watches_recursive(inotify_fd, full_path, config.flags, &config);
                    }
                }
            } else if (!is_dir_watch && event->wd < MAX_PATHS && config.watch_paths[event->wd]) {
                char full_path[PATH_MAX];
                int watch_updated = 0;
                int event_wd = event->wd;
                
                if (event->len > 0) {
                    snprintf(full_path, sizeof(full_path), "%s/%s", 
                            config.watch_paths[event_wd], event->name);
                } else {
                    strncpy(full_path, config.watch_paths[event_wd], PATH_MAX - 1);
                }

                // Check if file still exists for any event
                struct stat path_stat;
                if (stat(full_path, &path_stat) != 0) {
                    if (config.verbose) {
                        printf(DARK_GREY "+ File no longer exists: %s\n" RESET, full_path);
                    }
                    // Clean up watch path
                    free(config.watch_paths[event->wd]);
                    config.watch_paths[event->wd] = NULL;
                    
                    // Clean up cache path
                    if (config.cached_paths && config.cached_paths[event->wd]) {
                        if (config.verbose) {
                            printf(DARK_GREY "+ Removing cache for: %s\n" RESET, config.cached_paths[event->wd]);
                        }
                        unlink(config.cached_paths[event->wd]); // Remove cache file
                        free(config.cached_paths[event->wd]);
                        config.cached_paths[event->wd] = NULL;
                    }
                    i += EVENT_SIZE + event->len;
                    continue;
                }

                // IN_IGNORE is when text editors like helix save a file. 
                // We need to reapply the watch to the file in case the file was not deleted.
                if (event->mask & IN_IGNORED) {
                    watch_updated = 1;
                    struct stat path_stat;
                    if (stat(full_path, &path_stat) == 0) {  // File still exists
                        int new_wd = add_watch(inotify_fd, full_path, config.flags);
                        
                        if (new_wd != -1 && new_wd < MAX_PATHS) {
                            // Free old path if it exists at new_wd
                            if (config.watch_paths[new_wd]) {
                                free(config.watch_paths[new_wd]);
                            }
                            config.watch_paths[new_wd] = strdup(full_path);
                            if (event_wd != new_wd) {
                                config.cached_paths[new_wd] = config.cached_paths[event_wd];
                                config.cached_paths[event_wd] = NULL;
                            }

                            if (config.verbose) {
                                printf(DARK_GREY "+ Reapplied watch for %s\n" RESET, full_path);
                            }
                            event_wd = new_wd;
                        }
                    } else {
                        if (config.verbose) {
                            printf(DARK_GREY "+ File no longer exists: %s\n" RESET, full_path);
                        }
                        // Clean up the old watch path
                        free(config.watch_paths[event->wd]);
                        config.watch_paths[event->wd] = NULL;
                    }
                }

                // Handle the event as before
                char event_desc[32];
                snprintf(event_desc, sizeof(event_desc), "%s", 
                    event->mask & IN_MODIFY ? "Modified" :
                    event->mask & IN_CREATE ? "Created" :
                    event->mask & IN_DELETE ? "Deleted" :
                    event->mask & IN_MOVED_FROM ? "Moved from" :
                    event->mask & IN_MOVED_TO ? "Moved to" :
                    event->mask & IN_CLOSE_WRITE ? "Modified" :
                    event->mask & IN_CLOSE_NOWRITE ? "Closed" :
                    event->mask & IN_OPEN ? "Opened" :
                    event->mask & IN_ATTRIB ? "Attributes" :
                    event->mask & IN_DELETE_SELF ? "Self deleted" :
                    event->mask & IN_MOVE_SELF ? "Self moved" :
                    event->mask & IN_UNMOUNT ? "Unmounted" :
                    event->mask & IN_Q_OVERFLOW ? "Queue overflow" :
                    event->mask & IN_IGNORED ? "Watch removed" : "Unknown");

                if (now - last_event >= config.debounce_t || watch_updated) {
                    // Properly terminate any existing process group
                    if (g_last_pid > 0) {
                        // Send SIGTERM to the entire process group
                        killpg(g_last_pid, SIGTERM);
                        
                        // Wait a short time for graceful termination
                        struct timespec timeout = {0, 100000000}; // 100ms
                        nanosleep(&timeout, NULL);
                        
                        // If process still exists, force kill
                        if (kill(-g_last_pid, 0) == 0) {
                            killpg(g_last_pid, SIGKILL);
                        }
                        
                        // Wait for the process group to finish
                        while (waitpid(-g_last_pid, NULL, 0) > 0) {
                            // Continue waiting for all children
                        }
                        
                        g_last_pid = 0;
                    }
                    
                    if (!(event->mask & IN_IGNORED)) {
                        printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, 
                            config.watch_paths[event_wd], event_desc);
                    }

                    if (config.command != NULL) {
                        g_last_pid = fork();
                        if (g_last_pid == -1) {
                            perror("fork");
                            exit(EXIT_FAILURE);
                        }

                        if (g_last_pid == 0) {
                            // Child process
                            setpgid(0, 0);  // Create new process group
                            setvbuf(stdout, NULL, _IONBF, 0);
                            setvbuf(stderr, NULL, _IONBF, 0);
                            char *const args[] = {"/bin/sh", "-c", (char *)config.command, NULL};
                            execve("/bin/sh", args, environ);
                            perror("execve");
                            exit(EXIT_FAILURE);
                        }

                        // Parent continues without waiting
                    }
                    
                    if (cache_dir && config.diff_enabled) {
                        if (event->mask & (IN_MODIFY | IN_IGNORED)) {
                            char event_desc[256];
                            snprintf(event_desc, sizeof(event_desc), "Modified");
                            
                            run_diff(config.watch_paths[event_wd], 
                                cache_dir,
                                event_desc,
                                1, // diff is always verbose
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
    printf("Usage: sqwatch [-d directory] [-f file] [-t debounce time] -q event [-c command] [--diff] [-l log_file]\n");
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
    printf("  --diff            Enable diff functionality to show file changes\n");
    printf("  -l log_file       (Optional) Log file to write changes to (requires --diff)\n");
    printf("  -v                (Optional) Use verbose output (does not affect command output)\n");
    printf("  -h                Display this help message\n");
    printf("\nExamples:\n");
    printf("  sqwatch -d src -q modify --diff              # Watch src directory and show diffs\n");
    printf("  sqwatch -f config.txt -q all --diff -l changes.log  # Watch file with logging\n");
}
