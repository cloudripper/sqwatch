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

typedef struct {
    char *path;
    int wd;
} dir_watch;

typedef struct {
    char *watch_paths[MAX_PATHS];
    char *cached_paths[MAX_PATHS];
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
void handle_events(int inotify_fd, sqwatch_config config);
void print_usage(void);


#endif // SQWATCH_H
