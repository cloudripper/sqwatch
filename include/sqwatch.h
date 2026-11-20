#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

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
extern int stop_signal;     // -s, or 0 for the default, SIGTERM
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
    char *shown;             // The path as given: the displayed path of the root
} watch_root;

// A displayed path a watch is reached by. A file has one for each of its
// names (hard links) in the watched trees; a directory has one
typedef struct {
    char *path;
    int root;                // Index into roots
    unsigned seen;           // The last rescan that found it
} watch_name;

// A watched file or directory, by its watch descriptor
typedef struct {
    int wd;                  // -1 marks a free slot
    int is_dir;
    dev_t dev;               // The inode watched
    ino_t ino;
    watch_name *names;
    int name_count;
    char *cached;            // A file's cache entry, or NULL
    unsigned char changed;   // In the changed list: why (CHANGED_*)
    long long last_fire;     // When its last change was handled, in ms of
                             // CLOCK_MONOTONIC; 0 if never
    uint32_t pending;        // Events deferred to the end of its debounce
                             // window; non-zero while in the pending list
    struct timespec fired_ctime;  // Its status change time and size when its
    off_t fired_size;             // last change was handled
} watch_entry;

#define CHANGED_TAKEOVER 1   // Took over the cache entry of a name it replaced
#define CHANGED_CREATED 2    // The same, when it was created under the name
#define CHANGED_RESCAN 3     // Found to differ from its cache entry in a rescan

// Every watch, keyed by watch descriptor: open addressing with linear
// probing. The kernel hands out new descriptors as watches come and go, so
// there is no upper bound on their values and no limit on their number here
typedef struct {
    watch_entry *slots;
    size_t size;             // Number of slots: 0 or a power of two
    size_t count;            // Slots in use
} watch_table;

// Every watched name, to its watch descriptor: open addressing with linear
// probing, keyed by the displayed path. The path strings are the watch_name's
typedef struct {
    const char *path;        // NULL marks a free slot
    size_t hash;
    int wd;
} name_slot;

typedef struct {
    name_slot *slots;
    size_t size;
    size_t count;
} name_index;

typedef struct {
    watch_table watches;
    name_index names;
    unsigned scan;           // Rescans so far
    int creating;            // Watching an entry an IN_CREATE event named
    int *changed;            // Files to diff against their cache entry, as
    size_t changed_count;    // they may have changed without an event of
    size_t changed_size;     // their own (see mark_changed())
    int *pending;            // Files with events deferred by the debounce
    size_t pending_count;
    size_t pending_size;
    char **ignores;          // -i patterns
    int ignore_count;
    watch_root *roots;       // One per -d or -f
    int root_count;
    long long debounce_ms;   // The debounce time
    int debounce_set;        // Given with -t
    int wait;                // -w: let a running command finish
    int verbose;
    int diff_enabled;        // New flag for diff functionality
    const char *log_file;
    const char *command;
    uint32_t flags;
} sqwatch_config;

// What a directory watch gets beyond the events asked for, to follow the
// entries that come into the tree or leave it
#define DIR_WATCH_EVENTS (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO)




int add_watch(int inotify_fd, const char *path, int flags);
void add_watches_recursive(int inotify_fd, const char *path, uint32_t flags, sqwatch_config *config);
void cache_watched_files(sqwatch_config *config);
int handle_events(int inotify_fd, int signal_fd, sqwatch_config *config);
void print_usage(void);
watch_entry *watch_find(watch_table *table, int wd);
watch_entry *watch_add(watch_table *table, int wd);
void stop_if_signalled(void);
void stop_if_output_closed(void);
const char *printable(const char *path, char *buf, size_t size);
const char *shown_name(const char *name);
const char *shown_text(const char *text);


#endif // SQWATCH_H
