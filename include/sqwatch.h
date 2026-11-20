#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>

#include "diff.h"

#ifndef SQWATCH_H
#define SQWATCH_H

#define RED "\033[31m"
#define GREEN "\033[32m"
#define CYAN "\033[36m"
#define DARK_GREY "\033[90m"  // Added dark grey color
#define RESET "\033[0m"
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define MAX_PATHS 100
#define MAX_DIR_WATCHES 16


extern pid_t g_last_pid;
extern char *cache_dir;

// A path named on the command line. Symlinks in it are followed once, at
// startup; everything beneath it is then reached from fd without following any.
// The directory of a -f file is the exception: it is opened again by path when
// the file cannot be found in it any more
typedef struct {
    char *path;              // -d: prefix of the displayed paths of its entries;
                             // -f: the file's directory, as it is opened again
    int fd;                  // Directory all lookups start from
    char *rel;               // -f only: name of the watched file inside fd
} watch_root;

typedef struct {
    char *path;
    int wd;
    int root;                // Index into roots
} dir_watch;

typedef struct {
    char *watch_paths[MAX_PATHS];
    char *cached_paths[MAX_PATHS];
    int watch_roots[MAX_PATHS];  // Root of each file watch, by watch descriptor
    watch_root roots[MAX_PATHS];
    int root_count;
    int path_count;
    uint8_t debounce_t;
    int verbose;
    int diff_enabled;        // New flag for diff functionality
    const char *log_file;
    const char *command;
    uint32_t flags;
    dir_watch *dir_watches;  // Array for directory watches
    int dir_watch_count;
    int max_dir_watches;
} sqwatch_config;




int add_watch(int inotify_fd, const char *path, int flags);
void add_watches_recursive(int inotify_fd, const char *path, uint32_t flags, sqwatch_config *config);
void cache_watched_files(sqwatch_config *config);
int handle_events(int inotify_fd, int signal_fd, sqwatch_config config);
void print_usage(void);
void stop_if_signalled(void);
const char *printable(const char *path, char *buf, size_t size);


#endif // SQWATCH_H
