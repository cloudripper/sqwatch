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

// A watched file or directory, by its watch descriptor
typedef struct {
    int wd;                  // -1 marks a free slot
    int is_dir;
    char *path;              // Displayed path
    int root;                // Index into roots
    char *cached;            // A file's cache entry, or NULL
} watch_entry;

// Every watch, keyed by watch descriptor: open addressing with linear
// probing. The kernel hands out new descriptors as watches come and go, so
// there is no upper bound on their values and no limit on their number here
typedef struct {
    watch_entry *slots;
    size_t size;             // Number of slots: 0 or a power of two
    size_t count;            // Slots in use
} watch_table;

typedef struct {
    watch_table watches;
    watch_root *roots;       // One per -d or -f
    int root_count;
    uint8_t debounce_t;
    int verbose;
    int diff_enabled;        // New flag for diff functionality
    const char *log_file;
    const char *command;
    uint32_t flags;
} sqwatch_config;




int add_watch(int inotify_fd, const char *path, int flags);
void add_watches_recursive(int inotify_fd, const char *path, uint32_t flags, sqwatch_config *config);
void cache_watched_files(sqwatch_config *config);
int handle_events(int inotify_fd, int signal_fd, sqwatch_config *config);
void print_usage(void);
watch_entry *watch_find(watch_table *table, int wd);
watch_entry *watch_add(watch_table *table, int wd);
void watch_forget(watch_table *table, int wd);
void stop_if_signalled(void);
const char *printable(const char *path, char *buf, size_t size);
const char *shown_name(const char *name);
const char *shown_text(const char *text);


#endif // SQWATCH_H
