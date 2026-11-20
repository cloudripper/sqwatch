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

typedef struct dir_entry dir_entry;
typedef struct file_entry file_entry;
typedef struct inode_node inode_node;

// A file's content, as an inode: the cache entry of what it held when last
// seen, shared by all the watched names of the inode (hard links)
struct inode_node {
    dev_t dev;
    ino_t ino;
    char *cached;            // Its cache entry, or NULL
    file_entry **names;
    size_t count, size;
    inode_node *next;        // Chain of the inode table
};

// A watched directory, by its watch descriptor. Its watch also reports what
// happens to the files in it, by name: files get no watch of their own
struct dir_entry {
    int wd;
    char *path;              // Displayed path
    char *name;              // Name in its parent; NULL for a -d or -f root
    int root;                // Index into roots
    int full;                // Walked: every entry in it counts. Otherwise it
                             // is the directory of -f files only (see only)
    char **only;             // -f: the names in it that are watched
    int only_count;
    dev_t dev;
    ino_t ino;
    dir_entry *parent;
    size_t parent_at;        // Its index in parent->subdirs
    dir_entry **subdirs;
    size_t subdir_count, subdir_size;
    file_entry **files;
    size_t file_count, file_size;
    unsigned seen;           // The last rescan that found it
    dir_entry *next;         // Chains of the wd table and the name table
    dir_entry *name_next;
};

// A watched file: a name in a watched directory. Each name of a file with
// hard links is a file of its own
struct file_entry {
    dir_entry *dir;
    char *name;
    int root;                // Index into roots (a -f file has its own)
    size_t dir_at;           // Its index in dir->files
    inode_node *inode;       // What it named when last seen
    size_t inode_at;         // Its index in inode->names
    unsigned char changed;   // In the changed list: why (CHANGED_*)
    unsigned char fresh;     // Created at runtime, not written since
    size_t changed_at;
    long long last_fire;     // When its last change was handled, in ms of
                             // CLOCK_MONOTONIC; 0 if never
    uint32_t pending;        // Events deferred to the end of its debounce
    size_t pending_at;       // window; non-zero while in the pending list
    struct timespec fired_ctime;  // Its status change time and size when its
    off_t fired_size;             // last change was handled
    unsigned seen;           // The last rescan that found it
    file_entry *next;        // Chain of the name table
};

#define CHANGED_TAKEOVER 1   // Took over the cache entry of a name it replaced
#define CHANGED_CREATED 2    // The same, when it was created under the name
#define CHANGED_RESCAN 3     // Found to differ from its cache entry in a rescan
#define CHANGED_RETURNED 4   // Came back into the tree a moment after it left

// A hash table with chains; what the chains link depends on the table
typedef struct {
    void **buckets;
    size_t size;             // 0 or a power of two
    size_t count;
} chain_table;

typedef struct {
    chain_table dirs;        // dir_entry by wd
    chain_table dir_names;   // dir_entry by parent wd and name
    chain_table files;       // file_entry by directory wd and name
    chain_table inodes;      // inode_node by dev and ino
    int perm;                // -p: the command decides opens, nothing else
    int inotify_fd;
    unsigned scan;           // Rescans so far
    int creating;            // Watching an entry an IN_CREATE event named
    int watch_failed;        // Watches that could not be set: coverage is not whole
    file_entry **changed;    // Files to diff against their cache entry, as
    size_t changed_count;    // they may have changed without an event of
    size_t changed_size;     // their own (see mark_changed())
    file_entry **pending;    // Files with events deferred by the debounce
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
// entries that come into the tree or leave it, and to see its own end
#define DIR_WATCH_EVENTS (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | \
                          IN_DELETE_SELF | IN_MOVE_SELF)




int add_watch(int inotify_fd, const char *path, int flags);
void add_watches_recursive(int inotify_fd, const char *path, uint32_t flags, sqwatch_config *config);
void cache_watched_files(sqwatch_config *config);
int handle_events(int inotify_fd, int signal_fd, sqwatch_config *config);
void print_usage(void);
const char *watched_path(dev_t dev, ino_t ino);
void stop_if_signalled(void);
void stop_if_output_closed(void);
const char *printable(const char *path, char *buf, size_t size);
const char *shown_name(const char *name);
const char *shown_text(const char *text);


#endif // SQWATCH_H
