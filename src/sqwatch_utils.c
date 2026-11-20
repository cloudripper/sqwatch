#define _GNU_SOURCE  // O_PATH
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

#include "cache.h"
#include "sqwatch.h"
#include "diff.h"


// Room for "/proc/self/fd/" followed by any int
#define FD_PATH_LEN 32

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

// Copy a path for display, replacing control characters so a file name
// cannot inject terminal escapes or extra lines into the output
static const char *printable(const char *path, char *buf, size_t size) {
    size_t i = 0;
    for (; path[i] != '\0' && i + 1 < size; i++) {
        unsigned char c = (unsigned char)path[i];
        buf[i] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
    }
    buf[i] = '\0';
    return buf;
}

// Write the path that names whatever fd has open. Used through this path, a
// file or directory is the one that was opened and checked, no matter what its
// name in the watched tree points to by now
static const char *fd_path(int fd, char *buf, size_t size) {
    snprintf(buf, size, "/proc/self/fd/%d", fd);
    return buf;
}

// Watch exactly the inode fd refers to. The /proc link has to be followed to
// get there, so IN_DONT_FOLLOW must not be set
static int add_watch_fd(int inotify_fd, int fd, uint32_t flags) {
    char io_path[FD_PATH_LEN];
    return add_watch(inotify_fd, fd_path(fd, io_path, sizeof(io_path)), flags);
}

// Path of a watched entry relative to its root. Below a directory root every
// displayed path is "<root path>/<relative path>"; a file root has one entry
static const char *rel_path(const watch_root *root, const char *path) {
    if (root->rel) {
        return root->rel;
    }
    size_t len = strlen(root->path);
    return path[len] == '\0' ? "" : path + len + 1;
}

// Open rel beneath the directory root_fd without following a symlink in any
// component, the last one included. Every component is opened relative to the
// descriptor of the one before it, so renaming or replacing things in the tree
// cannot lead the lookup out of it. An empty rel is the root itself. Returns a
// descriptor, or -1 with errno set
static int open_beneath(int root_fd, const char *rel, int flags) {
    int dir_fd = root_fd;

    rel += strspn(rel, "/");
    if (*rel == '\0') {
        return openat(root_fd, ".", flags | O_NOFOLLOW | O_CLOEXEC);
    }

    while (1) {
        char name[NAME_MAX + 1];
        size_t len = strcspn(rel, "/");
        // Repeated slashes count as one separator
        const char *next = rel + len + strspn(rel + len, "/");
        int last = (*next == '\0');
        int fd = -1;

        if (len > NAME_MAX) {
            errno = ENAMETOOLONG;
        } else {
            memcpy(name, rel, len);
            name[len] = '\0';
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                errno = EINVAL;
            } else {
                fd = openat(dir_fd, name, last ? (flags | O_NOFOLLOW | O_CLOEXEC)
                            : (O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            }
        }

        int saved_errno = errno;
        if (dir_fd != root_fd) {
            close(dir_fd);
        }
        errno = saved_errno;

        if (fd == -1) {
            return -1;
        }
        if (last) {
            // O_PATH | O_NOFOLLOW opens a symlink itself instead of failing
            struct stat st;
            if ((flags & O_PATH) && (fstat(fd, &st) != 0 || S_ISLNK(st.st_mode))) {
                close(fd);
                errno = ELOOP;
                return -1;
            }
            return fd;
        }
        dir_fd = fd;
        rel = next;
    }
}

// Open the regular file `name` in the directory parent_fd without following a
// symlink. Returns an O_PATH descriptor, or -1 if it is not a regular file
static int open_file_at(int parent_fd, const char *name) {
    struct stat st;
    int fd = openat(parent_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd != -1 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))) {
        close(fd);
        fd = -1;
    }
    return fd;
}

// The directory of a -f file is the operator's path and may have been
// replaced since it was opened (moved aside and created again, or a symlink in
// it switched). Open it again by that path and use it from now on if it is a
// different directory. Returns 1 if root->fd changed
static int reopen_file_root(watch_root *root) {
    struct stat old_st, new_st;
    int fd = open(root->path, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1) {
        return 0;
    }
    if (fstat(fd, &new_st) == 0 && fstat(root->fd, &old_st) == 0 &&
        (new_st.st_dev != old_st.st_dev || new_st.st_ino != old_st.st_ino)) {
        close(root->fd);
        root->fd = fd;
        return 1;
    }
    close(fd);
    return 0;
}

// Add watches for the entry `name` of the directory parent_fd and, if it is a
// directory, for everything below it. path is the entry's displayed path.
// Entries are only ever reached relative to a descriptor and symlinks are not
// followed, so the walk cannot leave the tree it started in. at_runtime is set
// for a directory that appeared after startup: its files are cached here, as
// cache_watched_files() only covers the startup walk
static void add_watches_walk(int inotify_fd, int parent_fd, const char *name, const char *path,
                             int root, uint32_t flags, sqwatch_config *config, int at_runtime) {
    struct stat path_stat;
    if (fstatat(parent_fd, name, &path_stat, AT_SYMLINK_NOFOLLOW) == -1) {
        fprintf(stderr, RED "+ Failed to stat %s: %s\n" RESET, path, strerror(errno));
        return;
    }

    if (S_ISLNK(path_stat.st_mode)) {
        if (config->verbose) {
            printf(DARK_GREY "+ Skipping symlink %s\n" RESET, path);
        }
        return;
    }

    if (S_ISDIR(path_stat.st_mode)) {
        int dir_fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dir_fd == -1) {
            fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET, path, strerror(errno));
            return;
        }

        // Add directory watch separately from file watches
        int wd = add_watch_fd(inotify_fd, dir_fd, flags | IN_CREATE);
        if (wd != -1) {
            // Add to directory watches
            if (config->dir_watch_count >= config->max_dir_watches) {
                int new_size = config->max_dir_watches * 2;
                dir_watch *new_watches = realloc(config->dir_watches,
                                               new_size * sizeof(dir_watch));
                if (!new_watches) {
                    fprintf(stderr, RED "+ Failed to allocate memory for dir watches\n" RESET);
                    close(dir_fd);
                    return;
                }
                config->dir_watches = new_watches;
                config->max_dir_watches = new_size;
            }

            config->dir_watches[config->dir_watch_count].path = strdup(path);
            config->dir_watches[config->dir_watch_count].wd = wd;
            config->dir_watches[config->dir_watch_count].root = root;
            config->dir_watch_count++;

            if (config->verbose) {
                printf(CYAN "+ Watch set for directory %s\n" RESET, path);
            }
        }

        // Recurse into directory contents. The stream takes over dir_fd and
        // closedir() closes it
        DIR *dir = fdopendir(dir_fd);
        if (!dir) {
            fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET, path, strerror(errno));
            close(dir_fd);
            return;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char full_path[PATH_MAX];
            if (snprintf(full_path, sizeof(full_path), "%s/%s", path,
                         entry->d_name) >= (int)sizeof(full_path)) {
                fprintf(stderr, RED "+ Path too long, skipping %s/%s\n" RESET,
                        path, entry->d_name);
                continue;
            }
            add_watches_walk(inotify_fd, dir_fd, entry->d_name, full_path, root, flags, config,
                             at_runtime);
        }
        closedir(dir);
    } else if (S_ISREG(path_stat.st_mode)) {
        // Regular file handling remains unchanged
        int fd = open_file_at(parent_fd, name);
        int wd = fd == -1 ? -1 : add_watch_fd(inotify_fd, fd, flags);
        if (wd >= 0 && wd < MAX_PATHS) {
            config->watch_paths[wd] = strdup(path);
            config->watch_roots[wd] = root;
            config->path_count++;
            if (at_runtime && config->diff_enabled && cache_dir) {
                char io_path[FD_PATH_LEN];
                free(config->cached_paths[wd]);
                config->cached_paths[wd] = NULL;
                create_cache_for_file(path, fd_path(fd, io_path, sizeof(io_path)), cache_dir,
                                      &config->cached_paths[wd], config->verbose);
            }
            if (config->verbose) {
                printf(CYAN "+ Watch set for file %s\n" RESET, path);
            }
        }
        if (fd != -1) {
            close(fd);
        }
    }
}

// Start watching a path named on the command line. This and
// reopen_file_root() are the only places where symlinks are followed: the
// operator's path is trusted, what is found beneath it later is not
void add_watches_recursive(int inotify_fd, const char *path, uint32_t flags,
                           sqwatch_config *config) {
    struct stat path_stat;
    if (stat(path, &path_stat) == -1) {
        fprintf(stderr, RED "+ Failed to stat %s: %s\n" RESET, path, strerror(errno));
        return;
    }
    if (config->root_count >= MAX_PATHS) {
        return;
    }

    watch_root *root = &config->roots[config->root_count];
    const char *name = ".";
    root->path = NULL;
    root->rel = NULL;
    root->fd = -1;

    if (S_ISDIR(path_stat.st_mode)) {
        root->path = strdup(path);
        root->fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } else {
        // The directory part of the path is the operator's: it is opened
        // following symlinks, now and whenever the file has to be found
        // again. The file itself never is; if the path names a symlink, the
        // file it points to now is watched inside its real directory
        struct stat link_stat;
        char *given = lstat(path, &link_stat) == 0 && S_ISLNK(link_stat.st_mode) ?
            realpath(path, NULL) : strdup(path);
        char *dir = given ? strdup(given) : NULL;
        if (dir) {
            root->path = strdup(dirname(dir));
            root->rel = strdup(basename(given));
            if (root->path) {
                root->fd = open(root->path, O_PATH | O_DIRECTORY | O_CLOEXEC);
            }
        }
        name = root->rel;
        free(given);
        free(dir);
    }

    // A -f root is only walked if it names a regular file in its directory
    const char *error = NULL;
    if (root->fd == -1 || !root->path || !name) {
        error = strerror(errno);
    } else if (root->rel && fstatat(root->fd, root->rel, &path_stat, AT_SYMLINK_NOFOLLOW) != 0) {
        error = strerror(errno);
    } else if (root->rel && !S_ISREG(path_stat.st_mode)) {
        error = "not a regular file";
    }

    if (error) {
        char shown[PATH_MAX];
        fprintf(stderr, RED "+ Failed to open %s: %s\n" RESET,
                printable(path, shown, sizeof(shown)), error);
        if (root->fd != -1) {
            close(root->fd);
        }
        free(root->path);
        free(root->rel);
        return;
    }

    config->root_count++;
    add_watches_walk(inotify_fd, root->fd, name, path, config->root_count - 1, flags, config, 0);
}

// Copy every watched file into the cache at startup, overwriting what is
// there. Each file is opened beneath its root and read through that descriptor
void cache_watched_files(sqwatch_config *config) {
    for (int i = 0; i < MAX_PATHS; i++) {
        if (config->watch_paths[i] == NULL) {
            continue;
        }

        const watch_root *root = &config->roots[config->watch_roots[i]];
        struct stat st;
        char shown[PATH_MAX];
        int fd = open_beneath(root->fd, rel_path(root, config->watch_paths[i]), O_PATH);
        if (fd == -1) {
            fprintf(stderr, RED "+ Not caching %s: %s\n" RESET,
                    printable(config->watch_paths[i], shown, sizeof(shown)), strerror(errno));
            continue;
        }
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            fprintf(stderr, RED "+ Not caching %s: no longer a regular file\n" RESET,
                    printable(config->watch_paths[i], shown, sizeof(shown)));
            close(fd);
            continue;
        }

        char io_path[FD_PATH_LEN];
        char dest_path[PATH_MAX];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", cache_dir,
                 basename(config->watch_paths[i]));

        if (copy_file(fd_path(fd, io_path, sizeof(io_path)), dest_path) == 0) {
            config->cached_paths[i] = strdup(dest_path);
            if (config->verbose) {
                printf(DARK_GREY "+ Cached [%d]: %s -> %s\n" RESET, i, config->watch_paths[i],
                       dest_path);
            }
        }
        close(fd);
    }
}


// Terminate the process group of the previously started command, if any
static void stop_command(void) {
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
}

// Run the user's command in its own process group without waiting for it
static void start_command(const char *command) {
    if (command != NULL) {
        // Hold SIGTERM/SIGINT across fork so the child can never run the
        // handlers installed for sqwatch itself
        sigset_t block, prev;
        sigemptyset(&block);
        sigaddset(&block, SIGTERM);
        sigaddset(&block, SIGINT);
        sigprocmask(SIG_BLOCK, &block, &prev);

        g_last_pid = fork();
        if (g_last_pid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        }

        if (g_last_pid == 0) {
            // Child process
            signal(SIGTERM, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            setpgid(0, 0);  // Create new process group
            setvbuf(stdout, NULL, _IONBF, 0);
            setvbuf(stderr, NULL, _IONBF, 0);
            char *const args[] = {"/bin/sh", "-c", (char *)command, NULL};
            execve("/bin/sh", args, environ);
            perror("execve");
            exit(EXIT_FAILURE);
        }

        // Also set the group from the parent so a stop right after the
        // start cannot miss it; fails harmlessly once the child has exec'd
        setpgid(g_last_pid, g_last_pid);
        sigprocmask(SIG_SETMASK, &prev, NULL);
    }
}

void handle_events(int inotify_fd, sqwatch_config config) {
    char buffer[BUF_LEN];
    time_t last_event = 0;
    time_t last_create = 0;
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
        size_t i = 0;
        while (i + EVENT_SIZE <= (size_t)length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            // Reject invalid inotify descriptors
            if (event->wd < 0) {
                if (event->mask & IN_Q_OVERFLOW) {
                    fprintf(stderr,RED "+ inotify event queue overflowed; events lost\n" RESET);
                }
                i += EVENT_SIZE + event->len;
                continue;
            }

            // Check if this is a directory watch event
            int is_dir_watch = 0;
            char *dir_path = NULL;
            int dir_root = 0;
            for (int d = 0; d < config.dir_watch_count; d++) {
                if (config.dir_watches[d].wd == event->wd) {
                    is_dir_watch = 1;
                    dir_path = config.dir_watches[d].path;
                    dir_root = config.dir_watches[d].root;
                    break;
                }
            }

            if (is_dir_watch && (event->mask & IN_CREATE)) {
                char full_path[PATH_MAX];
                if (snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, event->name) >= (int)sizeof(full_path)) {
                    fprintf(stderr, RED "+ Path too long, skipping event\n" RESET);
                    i += EVENT_SIZE + event->len;
                    continue;
                }

                // Reach the directory from its root without following symlinks
                // and look at the new entry relative to that descriptor
                const watch_root *root = &config.roots[dir_root];
                int dir_fd = open_beneath(root->fd, rel_path(root, dir_path), O_PATH | O_DIRECTORY);
                struct stat path_stat;
                if (dir_fd != -1 && fstatat(dir_fd, event->name, &path_stat, AT_SYMLINK_NOFOLLOW) == 0) {
                    if (S_ISLNK(path_stat.st_mode)) {
                        if (config.verbose) {
                            printf(DARK_GREY "+ Skipping symlink %s\n" RESET, full_path);
                        }
                    } else if (S_ISREG(path_stat.st_mode)) {
                        // New file created - add watch
                        char io_path[FD_PATH_LEN];
                        int file_fd = open_file_at(dir_fd, event->name);
                        int new_wd = file_fd == -1 ? -1 :
                            add_watch(inotify_fd, fd_path(file_fd, io_path, sizeof(io_path)), config.flags);
                        if (new_wd >= 0 && new_wd < MAX_PATHS) {
                            // Free any existing path at this watch descriptor
                            if (config.watch_paths[new_wd]) {
                                free(config.watch_paths[new_wd]);
                            }
                            config.watch_paths[new_wd] = strdup(full_path);
                            config.watch_roots[new_wd] = dir_root;

                            // Free any existing cache path before creating new one
                            if (config.cached_paths[new_wd]) {
                                free(config.cached_paths[new_wd]);
                                config.cached_paths[new_wd] = NULL;
                            }

                            if (config.diff_enabled && cache_dir) {
                                create_cache_for_file(full_path, io_path, cache_dir, &config.cached_paths[new_wd], config.verbose);
                            }

                            if (config.verbose) {
                                printf(CYAN "+ Added watch for new file: %s\n" RESET, full_path);
                            }
                        }
                        if (file_fd != -1) {
                            close(file_fd);
                        }
                    } else if (S_ISDIR(path_stat.st_mode)) {
                        // New directory created - add recursive watches
                        add_watches_walk(inotify_fd, dir_fd, event->name, full_path, dir_root, config.flags, &config, 1);
                    }

                    // Directory watches always carry IN_CREATE to pick up new
                    // files; only run the command if create was requested.
                    // Creates are debounced on their own so they cannot
                    // swallow a write to the new file that follows
                    if ((config.flags & IN_CREATE) && now - last_create >= config.debounce_t) {
                        stop_command();
                        char shown[PATH_MAX];
                        printf(CYAN "+ Trigger on %s: [ Created ]\n" RESET,
                            printable(full_path, shown, sizeof(shown)));
                        start_command(config.command);
                        last_create = now;
                    }
                }
                if (dir_fd != -1) {
                    close(dir_fd);
                }
            } else if (!is_dir_watch && event->wd < MAX_PATHS && config.watch_paths[event->wd]) {
                char full_path[PATH_MAX];
                int watch_updated = 0;
                int event_wd = event->wd;
                int plen;
                if (event->len > 0) {
                    plen = snprintf(full_path, sizeof(full_path), "%s/%s", config.watch_paths[event_wd], event->name);
                } else {
                    plen = snprintf(full_path, sizeof(full_path), "%s", config.watch_paths[event_wd]);
                }

                if (plen < 0 || (size_t)plen >= sizeof(full_path)) {
                    fprintf(stderr, RED "+ Path too long, skipping event\n" RESET);
                    i += EVENT_SIZE + event->len;
                    continue;
                }

                // Check if file still exists for any event. It is opened once,
                // without following symlinks, and everything below acts on
                // this descriptor instead of resolving the path again
                watch_root *root = &config.roots[config.watch_roots[event_wd]];
                int file_fd = open_beneath(root->fd, rel_path(root, full_path), O_PATH);
                // A -f file may be gone because its directory was replaced:
                // look for it once more in what its directory path names now
                if (root->rel && ((event->mask & IN_IGNORED) ||
                                  (file_fd == -1 && (errno == ENOENT || errno == ENOTDIR))) &&
                    reopen_file_root(root)) {
                    if (file_fd != -1) {
                        close(file_fd);
                    }
                    file_fd = open_beneath(root->fd, rel_path(root, full_path), O_PATH);
                }
                struct stat path_stat;
                if (file_fd == -1 || fstat(file_fd, &path_stat) != 0 || !S_ISREG(path_stat.st_mode)) {
                    if (file_fd != -1) {
                        close(file_fd);
                    }
                    if (config.verbose) {
                        printf(DARK_GREY "+ File no longer exists: %s\n" RESET, full_path);
                    }
                    // Release the kernel watch too, or it stays for as long as
                    // the file lives elsewhere. After IN_IGNORED it is gone
                    if (!(event->mask & IN_IGNORED)) {
                        inotify_rm_watch(inotify_fd, event->wd);
                    }
                    // Clean up watch path
                    free(config.watch_paths[event->wd]);
                    config.watch_paths[event->wd] = NULL;

                    // Clean up cache path
                    if (config.cached_paths[event->wd]) {
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
                char io_path[FD_PATH_LEN];
                fd_path(file_fd, io_path, sizeof(io_path));

                // IN_IGNORE is when text editors like helix save a file.
                // We need to reapply the watch to the file in case the file was not deleted.
                if (event->mask & IN_IGNORED) {
                    watch_updated = 1;
                    int new_wd = add_watch(inotify_fd, io_path, config.flags);

                    if (new_wd >= 0 && new_wd < MAX_PATHS) {
                        // Free old path if it exists at new_wd
                        if (config.watch_paths[new_wd]) {
                            free(config.watch_paths[new_wd]);
                        }
                        config.watch_paths[new_wd] = strdup(full_path);
                        if (!config.watch_paths[new_wd]) {
                            fprintf(stderr, RED "+ Out of memory tracking %s\n" RESET, full_path);
                            close(file_fd);
                            i += EVENT_SIZE + event->len;
                            continue;
                        }
                        config.watch_roots[new_wd] = config.watch_roots[event_wd];
                        if (event_wd != new_wd) {
                            // The old watch is gone. new_wd may already have
                            // watched this file under another name (a temporary
                            // file renamed over it): drop that name's cache
                            free(config.watch_paths[event_wd]);
                            config.watch_paths[event_wd] = NULL;
                            if (config.cached_paths[new_wd] && (!config.cached_paths[event_wd] ||
                                strcmp(config.cached_paths[new_wd], config.cached_paths[event_wd]) != 0)) {
                                unlink(config.cached_paths[new_wd]);
                            }
                            free(config.cached_paths[new_wd]);
                            config.cached_paths[new_wd] = config.cached_paths[event_wd];
                            config.cached_paths[event_wd] = NULL;
                        }

                        if (config.verbose) {
                            printf(DARK_GREY "+ Reapplied watch for %s\n" RESET, full_path);
                        }
                        event_wd = new_wd;
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
                    stop_command();

                    if (!(event->mask & IN_IGNORED)) {
                        char shown[PATH_MAX];
                        printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET,
                            printable(config.watch_paths[event_wd], shown, sizeof(shown)),
                            event_desc);
                    }

                    start_command(config.command);

                    if (cache_dir && config.diff_enabled) {
                        if (event->mask & (IN_MODIFY | IN_IGNORED)) {
                            char event_desc[256];
                            snprintf(event_desc, sizeof(event_desc), "Modified");

                            run_diff(config.watch_paths[event_wd],
                                io_path,
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
                close(file_fd);
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
