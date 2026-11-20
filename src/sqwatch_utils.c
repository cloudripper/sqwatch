#define _GNU_SOURCE  // O_PATH
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <utime.h>
#include <libgen.h>
#include <sys/stat.h>
#include <limits.h>

#include "cache.h"
#include "sqwatch.h"
#include "diff.h"
#include "permission.h"


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

// Whether the valid n-byte UTF-8 sequence at p is a character that changes
// how text around it is shown without being visible itself: the bidirectional
// marks, embeddings, overrides and isolates (U+061C, U+200E, U+200F, U+202A to
// U+202E, U+2066 to U+2069), or a line or paragraph separator (U+2028,
// U+2029), which some readers take as the end of a line
static int is_format_char(const unsigned char *p, size_t n) {
    if (n == 2) {
        return p[0] == 0xd8 && p[1] == 0x9c;
    }
    if (n != 3 || p[0] != 0xe2) {
        return 0;
    }
    if (p[1] == 0x80) {
        return p[2] == 0x8e || p[2] == 0x8f || (p[2] >= 0xa8 && p[2] <= 0xae);
    }
    return p[1] == 0x81 && p[2] >= 0xa6 && p[2] <= 0xa9;
}

// Copy s into buf, escaped as escape() describes, stopping before the first
// character or escape that would not fit in limit bytes with the NUL after
// it. Returns the length written; *complete says whether all of s fitted
static size_t escape_into(const char *s, int allow_tab, char *buf, size_t limit,
                          int *complete) {
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *)s;
    size_t o = 0;
    *complete = 1;
    while (*p) {
        unsigned char c = *p;
        size_t n = 1;
        int ok;
        if (c < 0x80) {
            ok = (c >= 0x20 && c != 0x7f && c != '\\') || (allow_tab && c == '\t') ||
                 (allow_tab && c == '\r' && p[1] == '\0');
        } else if (c >= 0xc2 && c <= 0xdf) {
            n = 2;
            ok = (p[1] & 0xc0) == 0x80 && !(c == 0xc2 && p[1] < 0xa0);
        } else if (c >= 0xe0 && c <= 0xef) {
            n = 3;
            ok = (p[1] & 0xc0) == 0x80 && (p[2] & 0xc0) == 0x80 &&
                 !(c == 0xe0 && p[1] < 0xa0) && !(c == 0xed && p[1] >= 0xa0);
        } else if (c >= 0xf0 && c <= 0xf4) {
            n = 4;
            ok = (p[1] & 0xc0) == 0x80 && (p[2] & 0xc0) == 0x80 && (p[3] & 0xc0) == 0x80 &&
                 !(c == 0xf0 && p[1] < 0x90) && !(c == 0xf4 && p[1] >= 0x90);
        } else {
            ok = 0;
        }
        if (ok && is_format_char(p, n)) {
            // Every byte of it is written as \xHH: the lead byte here, the
            // others in turn, as continuation bytes on their own are invalid
            ok = 0;
        }
        if (!ok) {
            n = 1;
        }
        if (o + (ok ? n : 4) >= limit) {
            *complete = 0;
            break;
        }
        if (ok) {
            memcpy(buf + o, p, n);
            o += n;
        } else {
            buf[o++] = '\\';
            buf[o++] = 'x';
            buf[o++] = hex[c >> 4];
            buf[o++] = hex[c & 0xf];
        }
        p += n;
    }
    buf[o] = '\0';
    return o;
}

// Copy s for display with every byte that could act on a terminal, start a
// line of its own or be mistaken for something else written as \xHH: C0
// controls (a tab too, unless allow_tab), DEL, C1 controls whether UTF-8
// encoded (c2 80 to c2 9f) or raw, every byte that is not part of valid UTF-8,
// the invisible bidirectional and separator characters (see is_format_char())
// and the backslash itself, so that a literal "\x1b" in a name cannot pass for
// an escape. allow_tab is set for a line of a file's content: there a tab is
// kept, and so is a carriage return that ends the line (a CRLF file). Valid
// UTF-8 text is kept as it is. A copy that does not fit in size is cut short,
// never in the middle of a character or an escape, and ends in "..."
static const char *escape(const char *s, int allow_tab, char *buf, size_t size) {
    int complete;
    if (size == 0) {
        return "";
    }
    size_t o = escape_into(s, allow_tab, buf, size, &complete);
    if (!complete && size > 3) {
        o = escape_into(s, allow_tab, buf, size - 3, &complete);
        memcpy(buf + o, "...", 4);
    }
    return buf;
}

// A file name or path for display; see escape(). buf should hold
// 4 * PATH_MAX + 1 bytes, so that no path is cut
const char *printable(const char *path, char *buf, size_t size) {
    return escape(path, 0, buf, size);
}

// escape() into one of a few static buffers, to use straight in a printf();
// up to SHOWN_SLOTS results are valid at once
#define SHOWN_SLOTS 4
#define SHOWN_SIZE (4 * PATH_MAX + 1)
static const char *shown_slot(const char *s, int allow_tab) {
    static char slots[SHOWN_SLOTS][SHOWN_SIZE];
    static int next = 0;
    char *buf = slots[next];
    next = (next + 1) % SHOWN_SLOTS;
    return escape(s, allow_tab, buf, SHOWN_SIZE);
}

// A file name or path for display
const char *shown_name(const char *name) {
    return shown_slot(name, 0);
}

// A line of a watched file's content for display or the log: tabs are kept
const char *shown_text(const char *text) {
    return shown_slot(text, 1);
}

// Write the path that names whatever fd has open. Used through this path, a
// file or directory is the one that was opened and checked, no matter what its
// name in the watched tree points to by now
static const char *fd_path(int fd, char *buf, size_t size) {
    snprintf(buf, size, "/proc/self/fd/%d", fd);
    return buf;
}

// The events a directory watch carries. Its own watch reports, by name, what
// happens to the files in it: the events asked for, DIR_WATCH_EVENTS to follow
// the tree, and with open or access both close events, so that two opens or
// reads in a row are never merged into one by the kernel (it merges an event
// with the same one queued just before it). Files have no watch of their own
static uint32_t dir_watch_mask(uint32_t flags) {
    return flags | DIR_WATCH_EVENTS |
           (flags & (IN_OPEN | IN_ACCESS) ? IN_CLOSE_WRITE | IN_CLOSE_NOWRITE : 0);
}

#define READ_EVENTS (IN_OPEN | IN_ACCESS | IN_CLOSE_NOWRITE)

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

// ---- tables ---------------------------------------------------------------

static size_t hash_name(size_t seed, const char *name) {
    size_t h = 14695981039346656037u ^ (seed * 0x9E3779B97F4A7C15ull);
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        h = (h ^ *p) * 1099511628211u;
    }
    return h;
}

static size_t dir_hash(const void *e) {
    return (size_t)((unsigned)((const dir_entry *)e)->wd * 2654435761u);
}
static void **dir_link(void *e) {
    return (void **)&((dir_entry *)e)->next;
}
static size_t dir_name_hash(const void *e) {
    const dir_entry *d = e;
    return hash_name((size_t)d->parent->wd, d->name);
}
static void **dir_name_link(void *e) {
    return (void **)&((dir_entry *)e)->name_next;
}
static size_t file_hash(const void *e) {
    const file_entry *f = e;
    return hash_name((size_t)f->dir->wd, f->name);
}
static void **file_link(void *e) {
    return (void **)&((file_entry *)e)->next;
}
static size_t inode_hash(dev_t dev, ino_t ino) {
    return (size_t)(((uint64_t)ino * 0x9E3779B97F4A7C15ull) ^ ((uint64_t)dev * 0xC2B2AE3D27D4EB4Full));
}
static size_t node_hash(const void *e) {
    const inode_node *n = e;
    return inode_hash(n->dev, n->ino);
}
static void **node_link(void *e) {
    return (void **)&((inode_node *)e)->next;
}

// Put e in t under hash, growing t to keep the chains short. Returns -1 if
// memory runs out (e is then not in t)
static int chain_put(chain_table *t, void *e, size_t (*hash)(const void *),
                     void **(*link)(void *)) {
    if (t->count + 1 > t->size) {
        size_t new_size = t->size ? t->size * 2 : 64;
        void **buckets = calloc(new_size, sizeof(*buckets));
        if (!buckets) {
            if (t->size == 0) {
                return -1;
            }
        } else {
            for (size_t b = 0; b < t->size; b++) {
                void *x = t->buckets[b];
                while (x) {
                    void *next = *link(x);
                    size_t at = hash(x) & (new_size - 1);
                    *link(x) = buckets[at];
                    buckets[at] = x;
                    x = next;
                }
            }
            free(t->buckets);
            t->buckets = buckets;
            t->size = new_size;
        }
    }
    size_t at = hash(e) & (t->size - 1);
    *link(e) = t->buckets[at];
    t->buckets[at] = e;
    t->count++;
    return 0;
}

// Take e out of t, where it is under hash
static void chain_del(chain_table *t, void *e, size_t (*hash)(const void *),
                      void **(*link)(void *)) {
    if (t->size == 0) {
        return;
    }
    void **p = &t->buckets[hash(e) & (t->size - 1)];
    while (*p && *p != e) {
        p = link(*p);
    }
    if (*p) {
        *p = *link(e);
        *link(e) = NULL;
        t->count--;
    }
}

static dir_entry *dir_find(sqwatch_config *config, int wd) {
    if (config->dirs.size == 0 || wd < 0) {
        return NULL;
    }
    dir_entry *d = config->dirs.buckets[((unsigned)wd * 2654435761u) & (config->dirs.size - 1)];
    while (d && d->wd != wd) {
        d = d->next;
    }
    return d;
}

// The subdirectory `name` of parent, if it is watched
static dir_entry *dir_child(sqwatch_config *config, const dir_entry *parent, const char *name) {
    if (config->dir_names.size == 0) {
        return NULL;
    }
    size_t at = hash_name((size_t)parent->wd, name) & (config->dir_names.size - 1);
    dir_entry *d = config->dir_names.buckets[at];
    while (d && (d->parent != parent || strcmp(d->name, name) != 0)) {
        d = d->name_next;
    }
    return d;
}

static file_entry *file_find(sqwatch_config *config, const dir_entry *dir, const char *name) {
    if (config->files.size == 0) {
        return NULL;
    }
    size_t at = hash_name((size_t)dir->wd, name) & (config->files.size - 1);
    file_entry *f = config->files.buckets[at];
    while (f && (f->dir != dir || strcmp(f->name, name) != 0)) {
        f = f->next;
    }
    return f;
}

static inode_node *inode_find(sqwatch_config *config, dev_t dev, ino_t ino) {
    if (config->inodes.size == 0) {
        return NULL;
    }
    inode_node *n = config->inodes.buckets[inode_hash(dev, ino) & (config->inodes.size - 1)];
    while (n && (n->dev != dev || n->ino != ino)) {
        n = n->next;
    }
    return n;
}

// Append p to the array *a of *count, *size elements; returns -1 if memory
// runs out
static int push_ptr(void ***a, size_t *count, size_t *size, void *p) {
    if (*count == *size) {
        size_t new_size = *size ? *size * 2 : 8;
        void **grown = realloc(*a, new_size * sizeof(*grown));
        if (!grown) {
            return -1;
        }
        *a = grown;
        *size = new_size;
    }
    (*a)[(*count)++] = p;
    return 0;
}

// Take f off the names of its inode. An inode left without names is
// forgotten, with its cache entry
static void inode_leave(sqwatch_config *config, file_entry *f) {
    inode_node *n = f->inode;
    if (!n) {
        return;
    }
    file_entry *last = n->names[--n->count];
    n->names[f->inode_at] = last;
    last->inode_at = f->inode_at;
    f->inode = NULL;
    if (n->count == 0) {
        chain_del(&config->inodes, n, node_hash, node_link);
        if (n->cached) {
            unlink_cache_file(n->cached);
            free(n->cached);
        }
        free(n->names);
        free(n);
    }
}

// What f's name showed, for a name it is going to another file: its inode's
// cache entry itself if f is that inode's only name, else a copy. Owned by
// the caller; NULL if there is none
static char *take_history(sqwatch_config *config, file_entry *f) {
    inode_node *n = f->inode;
    if (!n || !n->cached) {
        return NULL;
    }
    if (n->count == 1) {
        char *history = n->cached;
        n->cached = NULL;
        return history;
    }
    (void)config;
    return cache_copy_entry(cache_dir, n->cached);
}

// Make history (owned) the cache entry of f's inode, unless other watched
// names share that inode: its entry is theirs too. Returns 1 if it did
static int give_history(file_entry *f, char *history) {
    inode_node *n = f->inode;
    if (!history) {
        return 0;
    }
    if (!n || n->count > 1) {
        unlink_cache_file(history);
        free(history);
        return 0;
    }
    if (n->cached) {
        unlink_cache_file(n->cached);
        free(n->cached);
    }
    n->cached = history;
    return 1;
}

// Record that f names the inode dev/ino now. With carry, a name that goes
// from one inode to another keeps its history: the new inode's cache entry
// becomes what the name showed (see give_history()). Returns 1 if f's inode
// changed and its history was carried
static int file_set_inode(sqwatch_config *config, file_entry *f, dev_t dev, ino_t ino,
                          int carry) {
    if (f->inode && f->inode->dev == dev && f->inode->ino == ino) {
        return 0;
    }
    char *history = carry ? take_history(config, f) : NULL;
    inode_leave(config, f);
    inode_node *n = inode_find(config, dev, ino);
    if (!n) {
        n = calloc(1, sizeof(*n));
        if (n) {
            n->dev = dev;
            n->ino = ino;
        }
        if (!n || chain_put(&config->inodes, n, node_hash, node_link) != 0) {
            free(n);
            if (history) {
                unlink_cache_file(history);
                free(history);
            }
            return 0;
        }
    }
    f->inode_at = n->count;
    if (push_ptr((void ***)&n->names, &n->count, &n->size, f) != 0) {
        if (history) {
            unlink_cache_file(history);
            free(history);
        }
        return 0;
    }
    f->inode = n;
    return give_history(f, history);
}

// The cache entry of f's content, or NULL
static const char *cache_of(const file_entry *f) {
    return f->inode ? f->inode->cached : NULL;
}

// The displayed path of f, in buf
static const char *file_path(const sqwatch_config *config, const file_entry *f, char *buf,
                             size_t size) {
    const watch_root *root = &config->roots[f->root];
    if (root->rel) {
        snprintf(buf, size, "%s", root->shown);
    } else if (snprintf(buf, size, "%s/%s", f->dir->path, f->name) >= (int)size) {
        return NULL;
    }
    return buf;
}

// Open the directory dir, as an O_PATH descriptor, beneath its root
static int open_dir(sqwatch_config *config, const dir_entry *dir) {
    watch_root *root = &config->roots[dir->root];
    if (root->rel) {
        return openat(root->fd, ".", O_PATH | O_DIRECTORY | O_CLOEXEC);
    }
    return open_beneath(root->fd, rel_path(root, dir->path), O_PATH | O_DIRECTORY);
}

// Open the file f names now, as an O_PATH descriptor of a regular file, or -1
static int open_file(sqwatch_config *config, const file_entry *f) {
    int dir_fd = open_dir(config, f->dir);
    int fd = dir_fd == -1 ? -1 : open_file_at(dir_fd, f->name);
    if (dir_fd != -1) {
        close(dir_fd);
    }
    return fd;
}

// sqwatch's own reads of a watched file (its copies, diffs and checks) must
// not show up as opens or accesses. Files are seen through the watch of their
// directory, so with -q open or -q access that watch drops the read events
// (quiet set) for the time of such a read, and gets them back after it. The
// kernel then queues no event for these reads at all. The price: a read of
// any file of that directory by another process in that moment is not seen
static void own_reads(sqwatch_config *config, const dir_entry *dir, int quiet) {
    if (!(config->flags & (IN_OPEN | IN_ACCESS))) {
        return;
    }
    int fd = open_dir(config, dir);
    if (fd != -1) {
        uint32_t mask = dir_watch_mask(config->flags);
        add_watch_fd(config->inotify_fd, fd, quiet ? mask & ~READ_EVENTS : mask);
        close(fd);
    }
}

// Remove p from the lists of files with pending events or marked changed
static void unlist(sqwatch_config *config, file_entry *f) {
    if (f->pending_at) {
        file_entry *last = config->pending[--config->pending_count];
        config->pending[f->pending_at - 1] = last;
        last->pending_at = f->pending_at;
        f->pending_at = 0;
        f->pending = 0;
    }
    if (f->changed_at) {
        file_entry *last = config->changed[--config->changed_count];
        config->changed[f->changed_at - 1] = last;
        last->changed_at = f->changed_at;
        f->changed_at = 0;
        f->changed = 0;
    }
}

// Forget the file f (and its inode's cache entry with its last name)
static void file_free(sqwatch_config *config, file_entry *f) {
    dir_entry *dir = f->dir;
    unlist(config, f);
    chain_del(&config->files, f, file_hash, file_link);
    inode_leave(config, f);
    file_entry *last = dir->files[--dir->file_count];
    dir->files[f->dir_at] = last;
    last->dir_at = f->dir_at;
    free(f->name);
    free(f);
}

// A new file entry for name in dir
static file_entry *file_add(sqwatch_config *config, dir_entry *dir, const char *name, int root) {
    file_entry *f = calloc(1, sizeof(*f));
    char *copy = strdup(name);
    if (!f || !copy) {
        free(f);
        free(copy);
        return NULL;
    }
    f->dir = dir;
    f->name = copy;
    f->root = root;
    f->dir_at = dir->file_count;
    if (push_ptr((void ***)&dir->files, &dir->file_count, &dir->file_size, f) != 0) {
        free(copy);
        free(f);
        return NULL;
    }
    if (chain_put(&config->files, f, file_hash, file_link) != 0) {
        dir->file_count--;
        free(copy);
        free(f);
        return NULL;
    }
    return f;
}

// Move f to the name `name` in dir
static int file_rename(sqwatch_config *config, file_entry *f, dir_entry *dir, const char *name) {
    char *copy = strdup(name);
    if (!copy) {
        return -1;
    }
    chain_del(&config->files, f, file_hash, file_link);
    if (dir != f->dir) {
        dir_entry *old = f->dir;
        file_entry *last = old->files[--old->file_count];
        old->files[f->dir_at] = last;
        last->dir_at = f->dir_at;
        f->dir_at = dir->file_count;
        if (push_ptr((void ***)&dir->files, &dir->file_count, &dir->file_size, f) != 0) {
            free(copy);
            file_free(config, f);
            return -1;
        }
        f->dir = dir;
        f->root = dir->root;
    }
    free(f->name);
    f->name = copy;
    chain_put(&config->files, f, file_hash, file_link);
    return 0;
}

// Take dir out of its parent's subdirectories and the name table
static void dir_unparent(sqwatch_config *config, dir_entry *dir) {
    if (!dir->parent) {
        return;
    }
    chain_del(&config->dir_names, dir, dir_name_hash, dir_name_link);
    dir_entry *parent = dir->parent;
    dir_entry *last = parent->subdirs[--parent->subdir_count];
    parent->subdirs[dir->parent_at] = last;
    last->parent_at = dir->parent_at;
    dir->parent = NULL;
}

// Make dir the subdirectory `name` of parent (NULL: a root)
static int dir_reparent(sqwatch_config *config, dir_entry *dir, dir_entry *parent,
                        const char *name) {
    dir_unparent(config, dir);
    free(dir->name);
    dir->name = NULL;
    if (!parent) {
        return 0;
    }
    dir->name = strdup(name);
    dir->parent_at = parent->subdir_count;
    if (!dir->name ||
        push_ptr((void ***)&parent->subdirs, &parent->subdir_count, &parent->subdir_size, dir)) {
        return -1;
    }
    dir->parent = parent;
    chain_put(&config->dir_names, dir, dir_name_hash, dir_name_link);
    return 0;
}

// Stop watching dir and everything beneath it: the kernel watches, unless
// watch_gone (the kernel took dir's own away already), and the files with
// their cache entries. Iterative, and it checks for signals as it goes
static void dir_drop(sqwatch_config *config, dir_entry *dir, int watch_gone) {
    dir_unparent(config, dir);
    dir_entry **stack = NULL;
    size_t depth = 0, size = 0, steps = 0;
    if (push_ptr((void ***)&stack, &depth, &size, dir) != 0) {
        return;
    }
    while (depth > 0) {
        dir_entry *d = stack[depth - 1];
        if ((++steps & 255) == 0) {
            stop_if_signalled();
        }
        if (d->subdir_count > 0) {
            dir_entry *sub = d->subdirs[d->subdir_count - 1];
            dir_unparent(config, sub);
            if (push_ptr((void ***)&stack, &depth, &size, sub) != 0) {
                break;
            }
            continue;
        }
        depth--;
        while (d->file_count > 0) {
            file_free(config, d->files[d->file_count - 1]);
        }
        if (d != dir || !watch_gone) {
            inotify_rm_watch(config->inotify_fd, d->wd);
        }
        chain_del(&config->dirs, d, dir_hash, dir_link);
        for (int i = 0; i < d->only_count; i++) {
            free(d->only[i]);
        }
        free(d->only);
        free(d->subdirs);
        free(d->files);
        free(d->path);
        free(d->name);
        free(d);
    }
    free(stack);
}

// Give dir and everything beneath it the displayed path that follows from
// path, after a rename
static void dir_repath(dir_entry *dir, const char *path) {
    dir_entry **stack = NULL;
    size_t depth = 0, size = 0;
    char *copy = strdup(path);
    if (!copy) {
        return;
    }
    free(dir->path);
    dir->path = copy;
    for (size_t i = 0; i < dir->subdir_count; i++) {
        push_ptr((void ***)&stack, &depth, &size, dir->subdirs[i]);
    }
    while (depth > 0) {
        dir_entry *d = stack[--depth];
        char *p;
        if (asprintf(&p, "%s/%s", d->parent->path, d->name) >= 0) {
            free(d->path);
            d->path = p;
        }
        for (size_t i = 0; i < d->subdir_count; i++) {
            push_ptr((void ***)&stack, &depth, &size, d->subdirs[i]);
        }
    }
    free(stack);
}

// Note that the file f has to be diffed against its cache entry: it took over
// the entry of a name it replaced (CHANGED_TAKEOVER, CHANGED_CREATED), or a
// rescan found it differs (CHANGED_RESCAN). handle_events() goes through the
// list
static void mark_changed(sqwatch_config *config, file_entry *f, unsigned char why) {
    if (f->changed_at) {
        return;
    }
    if (push_ptr((void ***)&config->changed, &config->changed_count, &config->changed_size, f)) {
        fprintf(stderr, RED "+ Out of memory, a change may not be shown\n" RESET);
        return;
    }
    f->changed_at = config->changed_count;
    f->changed = why;
}

// Whether the entry whose displayed path is path, in root, is ignored: it
// matches a -i pattern, or it is named .git. A pattern with a '/' is matched
// against the path relative to the root, '/' only matched by '/'; any other
// against the last component. What -d or -f names is never ignored
static int is_ignored(const sqwatch_config *config, int root, const char *path) {
    const char *rel = rel_path(&config->roots[root], path);
    if (*rel == '\0' || config->roots[root].rel) {
        return 0;  // A -d directory or a -f file itself
    }
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    if (strcmp(base, ".git") == 0) {
        return 1;
    }
    for (int i = 0; i < config->ignore_count; i++) {
        const char *pattern = config->ignores[i];
        if (strchr(pattern, '/') ? fnmatch(pattern, rel, FNM_PATHNAME) == 0 :
                                   fnmatch(pattern, base, 0) == 0) {
            return 1;
        }
    }
    return 0;
}

// A name that went away inside the tree, renamed to another watched name, or
// out of the tree with its history kept for a while: whatever is made under
// the old name soon after (an editor that moves the file aside to write a new
// one) takes over that history. A file moved out keeps its events not yet
// handled as well: if the same file comes back, under any watched name, it
// gets its history and those events back, so moving a file out and in again
// hides nothing
#define DEPARTED_SLOTS 64
#define DEPARTED_MS 3000
typedef struct {
    int wd;                  // Where the name was: directory wd and name
    char name[NAME_MAX + 1];
    int to_wd;               // Renamed: the file now has this name ...
    char to_name[NAME_MAX + 1];
    char *cached;            // ... else moved out: its cache entry, kept here
    dev_t dev;               // Moved out: the file, and what was known of it
    ino_t ino;
    uint32_t pending;
    long long last_fire;
    off_t fired_size;
    struct timespec fired_ctime;
    long long when;          // ms of CLOCK_MONOTONIC; 0: a free slot
} departed_name;
static departed_name departed[DEPARTED_SLOTS];
static void defer(sqwatch_config *config, file_entry *f, uint32_t mask);

static long long clock_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 1;
}

static void departed_clear(departed_name *d) {
    if (d->cached) {
        unlink_cache_file(d->cached);
        free(d->cached);
        d->cached = NULL;
    }
    d->when = 0;
}

// Remember that name left dir; to (when it was renamed within the tree) is
// where the file went, else gone (moved out) is the file that left, whose
// cache entry, cached, is kept here, unless another name still has it
static void departed_add(const dir_entry *dir, const char *name, const file_entry *to,
                         const file_entry *gone, char *cached) {
    long long now = clock_ms();
    departed_name *slot = &departed[0];
    for (int i = 0; i < DEPARTED_SLOTS; i++) {
        if (departed[i].when == 0 || now - departed[i].when > DEPARTED_MS) {
            slot = &departed[i];
            break;
        }
        if (departed[i].when < slot->when) {
            slot = &departed[i];
        }
    }
    departed_clear(slot);
    if (strlen(name) > NAME_MAX || (to && strlen(to->name) > NAME_MAX)) {
        if (cached) {
            unlink_cache_file(cached);
            free(cached);
        }
        return;
    }
    slot->wd = dir->wd;
    strcpy(slot->name, name);
    slot->to_wd = to ? to->dir->wd : -1;
    strcpy(slot->to_name, to ? to->name : "");
    slot->cached = cached;
    slot->dev = gone && gone->inode ? gone->inode->dev : 0;
    slot->ino = gone && gone->inode ? gone->inode->ino : 0;
    slot->pending = gone ? gone->pending : 0;
    slot->last_fire = gone ? gone->last_fire : 0;
    slot->fired_size = gone ? gone->fired_size : 0;
    slot->fired_ctime = gone ? gone->fired_ctime : (struct timespec){0, 0};
    slot->when = now;
}

// Forget the departed names older than DEPARTED_MS, or all of them; returns
// the ms until the next one expires, or -1
static long long departed_expire(int all) {
    long long now = clock_ms(), next = -1;
    for (int i = 0; i < DEPARTED_SLOTS; i++) {
        if (departed[i].when == 0) {
            continue;
        }
        long long left = departed[i].when + DEPARTED_MS - now;
        if (all || left <= 0) {
            departed_clear(&departed[i]);
        } else if (next < 0 || left < next) {
            next = left;
        }
    }
    return next;
}

// The new file f takes over the history of its name if the name left a
// moment ago: the cache entry of the file that had it (which gets a fresh
// copy of its own), or the one kept for it. A file that left the tree a
// moment ago and came back, under whatever name, gets its own history back,
// and its events not yet handled, which are handled now (CHANGED_RETURNED).
// Returns 1 if f took over a history
static int take_departed(sqwatch_config *config, file_entry *f) {
    long long now = clock_ms();
    for (int i = 0; f->inode && i < DEPARTED_SLOTS; i++) {
        departed_name *d = &departed[i];
        if (d->when == 0 || now - d->when > DEPARTED_MS || d->to_wd != -1 ||
            d->dev != f->inode->dev || d->ino != f->inode->ino || (!d->dev && !d->ino)) {
            continue;
        }
        char *history = d->cached;
        d->cached = NULL;
        d->when = 0;
        give_history(f, history);
        f->last_fire = d->last_fire;
        f->fired_size = d->fired_size;
        f->fired_ctime = d->fired_ctime;
        if (d->pending) {
            defer(config, f, d->pending);
        }
        mark_changed(config, f, CHANGED_RETURNED);
        return 1;
    }
    for (int i = 0; i < DEPARTED_SLOTS; i++) {
        departed_name *d = &departed[i];
        if (d->when == 0 || now - d->when > DEPARTED_MS || d->wd != f->dir->wd ||
            strcmp(d->name, f->name) != 0) {
            continue;
        }
        char *history = NULL;
        if (d->cached) {
            history = d->cached;
            d->cached = NULL;
        } else {
            // Renamed: the file under its new name keeps its entry, which
            // still holds what this name showed; the new file gets a copy
            dir_entry *to_dir = dir_find(config, d->to_wd);
            file_entry *to = to_dir ? file_find(config, to_dir, d->to_name) : NULL;
            if (to && cache_of(to)) {
                history = cache_copy_entry(cache_dir, cache_of(to));
            }
        }
        d->when = 0;
        if (!give_history(f, history)) {
            return 0;
        }
        mark_changed(config, f, config->creating ? CHANGED_CREATED : CHANGED_TAKEOVER);
        return 1;
    }
    return 0;
}

// Watch the regular file `name` in the directory dir, open as dir_fd; path is
// its displayed path. A file found after startup (at_runtime) is cached here,
// if it has no cache entry yet; at_runtime 2 is a file that was just created
// or moved into the tree. root is the -f root of a -f file, else dir's.
// Returns the entry, or NULL
static file_entry *watch_file(sqwatch_config *config, dir_entry *dir, int dir_fd,
                              const char *name, const char *path, int root, int at_runtime) {
    if (is_ignored(config, root, path)) {
        if (config->verbose) {
            printf(DARK_GREY "+ Ignoring %s\n" RESET, shown_name(path));
        }
        return NULL;
    }
    int fd = open_file_at(dir_fd, name);
    struct stat st;
    if (fd == -1 || fstat(fd, &st) != 0) {
        if (fd != -1) {
            close(fd);
        }
        return NULL;
    }
    if (is_log_file(fd) || is_log_name(dir_fd, name)) {
        if (config->verbose) {
            printf(DARK_GREY "+ Not watching the log file %s\n" RESET, shown_name(path));
        }
        close(fd);
        return NULL;
    }
    file_entry *f = file_find(config, dir, name);
    int added = !f;
    if (added) {
        f = file_add(config, dir, name, root);
        if (!f) {
            fprintf(stderr, RED "+ Out of memory, not watching %s\n" RESET, shown_name(path));
            close(fd);
            return NULL;
        }
    }
    f->seen = config->scan;
    if (file_set_inode(config, f, st.st_dev, st.st_ino, !added)) {
        // Replaced since it was seen (events were lost): diff it against what
        // the name showed
        mark_changed(config, f, CHANGED_TAKEOVER);
    }
    char io_path[FD_PATH_LEN];
    fd_path(fd, io_path, sizeof(io_path));
    // A directory's mark covers its files; a -f file is marked on its own
    if (perm_active() && config->roots[root].rel) {
        perm_mark(io_path, 0);
    }
    if (added && at_runtime) {
        take_departed(config, f);
    }
    if (at_runtime && config->diff_enabled && cache_dir && f->inode && !f->inode->cached) {
        own_reads(config, dir, 1);
        create_cache_for_file(path, io_path, cache_dir, &f->inode->cached, config->verbose);
        own_reads(config, dir, 0);
    }
    if (added && config->rescanning) {
        printf(CYAN "+ Trigger on %s: [ %s ] (found by the walk after lost events)\n" RESET,
               shown_name(path), "Created");
    }
    if (added && config->verbose) {
        if (at_runtime == 2) {
            printf(CYAN "+ Added watch for new file: %s\n" RESET, shown_name(path));
        } else {
            printf(CYAN "+ Watch set for file %s\n" RESET, shown_name(path));
        }
    }
    close(fd);
    return f;
}

// Say once, loudly, that a watch could not be set: what is beneath that
// directory is not seen. The event loop treats it like lost events
static void watch_failed(sqwatch_config *config, const char *path, int error) {
    if (!config->watch_failed) {
        fprintf(stderr, RED "+ Cannot watch %s: %s. sqwatch does not see everything now: "
                "changes beneath it are missed%s\n" RESET, shown_name(path), strerror(error),
                error == ENOSPC ? " (the inotify watch limit, fs.inotify.max_user_watches, "
                                  "is reached)" : "");
    }
    config->watch_failed++;
}

// Watch the directory dir_fd refers to; path is its displayed path, name its
// name in parent (NULL for a root). A directory watched before (walked again,
// or renamed) gets the wd it already has: its entry is updated. Returns the
// entry, or NULL
static dir_entry *watch_dir(sqwatch_config *config, int dir_fd, const char *path,
                            dir_entry *parent, const char *name, int root, int full) {
    int wd = add_watch_fd(config->inotify_fd, dir_fd, dir_watch_mask(config->flags));
    if (wd < 0) {
        watch_failed(config, path, errno);
        return NULL;
    }
    struct stat st;
    dir_entry *dir = dir_find(config, wd);
    if (dir) {
        if (strcmp(dir->path, path) != 0 || dir->parent != parent) {
            if (dir_reparent(config, dir, parent, name) == 0) {
                dir_repath(dir, path);
            }
        }
        dir->full |= full;
        dir->seen = config->scan;
        return dir;
    }
    dir = calloc(1, sizeof(*dir));
    char *copy = strdup(path);
    if (!dir || !copy || fstat(dir_fd, &st) != 0) {
        free(dir);
        free(copy);
        inotify_rm_watch(config->inotify_fd, wd);
        fprintf(stderr, RED "+ Out of memory, not watching %s\n" RESET, shown_name(path));
        return NULL;
    }
    dir->wd = wd;
    dir->path = copy;
    dir->root = root;
    dir->full = full;
    dir->dev = st.st_dev;
    dir->ino = st.st_ino;
    dir->seen = config->scan;
    if (chain_put(&config->dirs, dir, dir_hash, dir_link) != 0 ||
        dir_reparent(config, dir, parent, name) != 0) {
        fprintf(stderr, RED "+ Out of memory, not watching %s\n" RESET, shown_name(path));
        dir_drop(config, dir, 0);
        return NULL;
    }
    if (perm_active()) {
        char io_path[FD_PATH_LEN];
        perm_mark(fd_path(dir_fd, io_path, sizeof(io_path)), 1);
    }
    if (config->verbose) {
        printf(CYAN "+ Watch set for directory %s\n" RESET, shown_name(path));
    }
    return dir;
}

// A directory the walk is in, from where it started down to the current one
typedef struct {
    char **names;            // Its subdirectories, in readdir order
    size_t count;            // Number of names
    size_t next;             // Index of the next name to look at
    dev_t dev;               // The directory found and watched, to know it
    ino_t ino;               // again when the walk comes back to it
    size_t path_len;         // Length of its displayed path in the path buffer
    dir_entry *dir;          // Its entry
} walk_level;

static void free_level(walk_level *level) {
    for (size_t i = 0; i < level->count; i++) {
        free(level->names[i]);
    }
    free(level->names);
}

// Whether fd is the directory a level was made for
static int is_level_dir(int fd, const walk_level *level) {
    struct stat st;
    return fstat(fd, &st) == 0 && st.st_dev == level->dev && st.st_ino == level->ino;
}

// Read the directory fd refers to, whose displayed path is in the walk's path
// buffer (PATH_MAX bytes). Regular files are watched and symlinks reported as
// they are read; only the names of subdirectories are kept in level, to be
// walked later, so a directory with many entries costs memory only for its
// subdirectories. The type comes from readdir(), or from fstatat() on a
// filesystem that does not give it. fd stays open and usable. Returns -1 with
// errno set if the directory cannot be read
static int read_names(sqwatch_config *config, int fd, char *path, int root, int at_runtime,
                      walk_level *level) {
    int dir_fd = dup(fd);
    DIR *dir = dir_fd == -1 ? NULL : fdopendir(dir_fd);
    if (!dir) {
        int saved_errno = errno;
        if (dir_fd != -1) {
            close(dir_fd);
        }
        errno = saved_errno;
        return -1;
    }
    size_t len = strlen(path), size = 0, seen = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if ((++seen & 255) == 0) {
            stop_if_signalled();
        }
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        unsigned char type = entry->d_type;
        if (type != DT_DIR && type != DT_REG && type != DT_LNK && type != DT_UNKNOWN) {
            continue;  // FIFOs, sockets and devices are not watched
        }
        if (type != DT_DIR) {
            if (snprintf(path + len, PATH_MAX - len, "/%s", name) >= (int)(PATH_MAX - len)) {
                path[len] = '\0';
                fprintf(stderr, RED "+ Path too long, skipping %s/%s\n" RESET, shown_name(path),
                        shown_name(name));
                continue;
            }
            struct stat st;
            if (type == DT_UNKNOWN) {
                if (fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
                    fprintf(stderr, RED "+ Failed to stat %s: %s\n" RESET, shown_name(path),
                            strerror(errno));
                    path[len] = '\0';
                    continue;
                }
                type = S_ISDIR(st.st_mode) ? DT_DIR : S_ISREG(st.st_mode) ? DT_REG :
                       S_ISLNK(st.st_mode) ? DT_LNK : DT_UNKNOWN;
            }
            if (type == DT_LNK && config->verbose) {
                printf(DARK_GREY "+ Skipping symlink %s\n" RESET, shown_name(path));
            } else if (type == DT_REG) {
                watch_file(config, level->dir, fd, name, path, root, at_runtime);
            }
            path[len] = '\0';
            if (type != DT_DIR) {
                continue;
            }
        }
        if (level->count == size) {
            size_t new_size = size ? size * 2 : 16;
            char **grown = realloc(level->names, new_size * sizeof(*grown));
            if (!grown) {
                break;
            }
            level->names = grown;
            size = new_size;
        }
        char *copy = strdup(name);
        if (!copy) {
            break;
        }
        level->names[level->count++] = copy;
    }
    if (entry) {
        fprintf(stderr, RED "+ Out of memory, not watching all of %s\n" RESET, shown_name(path));
    }
    closedir(dir);
    return 0;
}

// Watch the directory fd refers to, whose displayed path is the walk's path
// buffer and whose name in parent is name, watch its files and make it the
// innermost level, holding its subdirectories. Returns 0 if it could not be
// read; fd is the caller's either way
static int enter_dir(sqwatch_config *config, int fd, char *path, dir_entry *parent,
                     const char *name, int root, int at_runtime, walk_level **levels,
                     size_t *depth, size_t *size) {
    struct stat st;
    // An ignored directory, or sqwatch's own cache, is neither watched nor
    // walked
    if (is_ignored(config, root, path) || is_cache_dir(fd)) {
        if (config->verbose) {
            printf(DARK_GREY "+ Ignoring %s\n" RESET, shown_name(path));
        }
        return 0;
    }
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET, shown_name(path),
                strerror(errno));
        return 0;
    }
    if (*depth == *size) {
        size_t new_size = *size ? *size * 2 : 16;
        walk_level *grown = realloc(*levels, new_size * sizeof(*grown));
        if (!grown) {
            fprintf(stderr, RED "+ Out of memory, not watching %s\n" RESET,
                    shown_name(path));
            return 0;
        }
        *levels = grown;
        *size = new_size;
    }
    dir_entry *dir = watch_dir(config, fd, path, parent, name, root, 1);
    if (!dir) {
        return 0;  // Without a watch nothing beneath it would be seen
    }
    walk_level *level = &(*levels)[*depth];
    *level = (walk_level){NULL, 0, 0, st.st_dev, st.st_ino, strlen(path), dir};
    if (read_names(config, fd, path, root, at_runtime, level) != 0) {
        fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET, shown_name(path),
                strerror(errno));
        return 0;
    }
    (*depth)++;
    return 1;
}

// Get back to the innermost level's directory after its subdirectory child_fd
// is done, which this closes. ".." of the subdirectory is used if it is still
// that directory. If not, the subdirectory was moved, or the directory was:
// it is opened again from the root by its displayed path, and if that is not
// it either, the rest of it is given up and the walk goes on with the level
// above. Returns a descriptor of the innermost level left, or -1 if none is
static int climb(int child_fd, const watch_root *top, char *path, walk_level *levels,
                 size_t *depth) {
    int fd = openat(child_fd, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(child_fd);
    while (*depth > 0) {
        walk_level *level = &levels[*depth - 1];
        path[level->path_len] = '\0';
        if (fd != -1 && is_level_dir(fd, level)) {
            return fd;
        }
        if (fd != -1) {
            close(fd);
        }
        fd = open_beneath(top->fd, rel_path(top, path), O_RDONLY | O_DIRECTORY);
        if (fd != -1 && is_level_dir(fd, level)) {
            return fd;
        }
        if (fd != -1) {
            close(fd);
            fd = -1;
        }
        fprintf(stderr, RED "+ %s was moved or replaced, not watching the rest of it\n" RESET,
                shown_name(path));
        free_level(level);
        (*depth)--;
    }
    return -1;
}

// Add watches for the entry `name` of the directory parent (open as
// parent_fd; NULL for a -d root, whose parent_fd is the root and name ".")
// and, if it is a directory, for everything below it. path is the entry's
// displayed path. The walk is depth first. The files of a directory are
// watched while it is read, before any of its subdirectories is entered. It
// holds one descriptor, of the directory it is in, and keeps the names of the
// subdirectories still to walk of each directory on the way down on the heap:
// there is no recursion and no descriptor held per level, however deep the
// tree. Directories are entered with openat() relative to the current one and
// left through "..", checked to be the directory entered before; symlinks are
// never followed, so the walk cannot leave the tree it started in. at_runtime
// is set for an entry found after startup: its files are cached here, as
// cache_watched_files() only covers the startup walk; see watch_file()
static void add_watches_walk(sqwatch_config *config, dir_entry *parent, int parent_fd,
                             const char *name, const char *path, int root, int at_runtime) {
    const watch_root *top = &config->roots[root];
    struct stat path_stat;
    if (fstatat(parent_fd, name, &path_stat, AT_SYMLINK_NOFOLLOW) == -1) {
        fprintf(stderr, RED "+ Failed to stat %s: %s\n" RESET, shown_name(path), strerror(errno));
        return;
    }

    if (S_ISLNK(path_stat.st_mode)) {
        if (config->verbose) {
            printf(DARK_GREY "+ Skipping symlink %s\n" RESET, shown_name(path));
        }
        return;
    }

    if (S_ISREG(path_stat.st_mode)) {
        if (parent) {
            watch_file(config, parent, parent_fd, name, path, root, at_runtime);
        }
        return;
    }

    if (!S_ISDIR(path_stat.st_mode) || top->rel) {
        return;
    }
    if (at_runtime) {
        at_runtime = 1;  // What is beneath was not created on its own
    }

    char dir_path[PATH_MAX];
    if (snprintf(dir_path, sizeof(dir_path), "%s", path) >= (int)sizeof(dir_path)) {
        fprintf(stderr, RED "+ Path too long, skipping %s\n" RESET, shown_name(path));
        return;
    }
    int cur = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cur == -1) {
        fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET, shown_name(path),
                strerror(errno));
        return;
    }

    walk_level *levels = NULL;
    size_t depth = 0, size = 0;
    if (!enter_dir(config, cur, dir_path, parent, parent ? name : NULL, root, at_runtime,
                   &levels, &depth, &size)) {
        close(cur);
        free(levels);
        return;
    }

    while (depth > 0) {
        stop_if_signalled();
        walk_level *level = &levels[depth - 1];
        if (level->next == level->count) {
            free_level(level);
            depth--;
            if (depth > 0) {
                cur = climb(cur, top, dir_path, levels, &depth);
            } else {
                close(cur);
            }
            continue;
        }

        const char *entry = level->names[level->next++];
        size_t len = level->path_len;
        if (snprintf(dir_path + len, sizeof(dir_path) - len, "/%s", entry) >=
            (int)(sizeof(dir_path) - len)) {
            dir_path[len] = '\0';
            fprintf(stderr, RED "+ Path too long, skipping %s/%s\n" RESET,
                    shown_name(dir_path), shown_name(entry));
            continue;
        }

        struct stat st;
        if (fstatat(cur, entry, &st, AT_SYMLINK_NOFOLLOW) == -1) {
            fprintf(stderr, RED "+ Failed to stat %s: %s\n" RESET, shown_name(dir_path),
                    strerror(errno));
        } else if (S_ISLNK(st.st_mode)) {
            if (config->verbose) {
                printf(DARK_GREY "+ Skipping symlink %s\n" RESET, shown_name(dir_path));
            }
        } else if (S_ISREG(st.st_mode)) {
            watch_file(config, level->dir, cur, entry, dir_path, root, at_runtime);
        } else if (S_ISDIR(st.st_mode)) {
            int fd = openat(cur, entry, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd == -1) {
                fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET,
                        shown_name(dir_path),
                        strerror(errno));
            } else if (enter_dir(config, fd, dir_path, level->dir, entry, root, at_runtime,
                                 &levels, &depth, &size)) {
                close(cur);
                cur = fd;
                continue;
            } else {
                close(fd);
            }
        }
        dir_path[len] = '\0';
    }
    free(levels);
}

// Watch the file of the -f root r through its directory: the directory's
// watch, limited to that name unless the directory is walked anyway
static void watch_file_root(sqwatch_config *config, int r, int at_runtime) {
    watch_root *root = &config->roots[r];
    dir_entry *dir = watch_dir(config, root->fd, root->path, NULL, NULL, r, 0);
    if (!dir) {
        return;
    }
    int listed = 0;
    for (int i = 0; i < dir->only_count; i++) {
        listed |= strcmp(dir->only[i], root->rel) == 0;
    }
    if (!listed) {
        char **grown = realloc(dir->only, (dir->only_count + 1) * sizeof(*grown));
        char *copy = strdup(root->rel);
        if (!grown || !copy) {
            free(copy);
            if (grown) {
                dir->only = grown;
            }
            fprintf(stderr, RED "+ Out of memory, not watching %s\n" RESET,
                    shown_name(root->shown));
            return;
        }
        dir->only = grown;
        dir->only[dir->only_count++] = copy;
    }
    watch_file(config, dir, root->fd, root->rel, root->shown, r, at_runtime);
}

// Start watching a path named on the command line. This and
// reopen_file_root() are the only places where symlinks are followed: the
// operator's path is trusted, what is found beneath it later is not
void add_watches_recursive(int inotify_fd, const char *path, uint32_t flags,
                           sqwatch_config *config) {
    (void)inotify_fd;
    (void)flags;
    struct stat path_stat;
    if (stat(path, &path_stat) == -1) {
        fprintf(stderr, RED "+ Failed to stat %s: %s\n" RESET, shown_name(path), strerror(errno));
        return;
    }
    watch_root *root = &config->roots[config->root_count];
    root->path = NULL;
    root->rel = NULL;
    root->fd = -1;
    root->shown = strdup(path);

    if (S_ISDIR(path_stat.st_mode)) {
        // A trailing '/' is dropped, so that paths below read "d/f"
        root->path = strdup(path);
        size_t len = root->path ? strlen(root->path) : 0;
        while (len > 1 && root->path[len - 1] == '/') {
            root->path[--len] = '\0';
        }
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
        free(given);
        free(dir);
    }

    // A -f root is only watched if it names a regular file in its directory
    const char *error = NULL;
    if (root->fd == -1 || !root->path || !root->shown || (!S_ISDIR(path_stat.st_mode) &&
                                                           !root->rel)) {
        error = strerror(errno);
    } else if (root->rel && fstatat(root->fd, root->rel, &path_stat, AT_SYMLINK_NOFOLLOW) != 0) {
        error = strerror(errno);
    } else if (root->rel && !S_ISREG(path_stat.st_mode)) {
        error = "not a regular file";
    }

    if (error) {
        fprintf(stderr, RED "+ Failed to open %s: %s\n" RESET,
                shown_name(path), error);
        if (root->fd != -1) {
            close(root->fd);
        }
        free(root->path);
        free(root->rel);
        free(root->shown);
        return;
    }

    int r = config->root_count++;
    if (root->rel) {
        watch_file_root(config, r, 0);
    } else {
        add_watches_walk(config, NULL, root->fd, ".", root->path, r, 0);
    }
}

// Every file entry, in an array to free; *count is set to their number. NULL
// if there are none or memory runs out
static file_entry **file_list(sqwatch_config *config, size_t *count) {
    file_entry **files = config->files.count ? malloc(config->files.count * sizeof(*files)) :
                                               NULL;
    *count = 0;
    for (size_t b = 0; files && b < config->files.size; b++) {
        for (file_entry *f = config->files.buckets[b]; f; f = f->next) {
            files[(*count)++] = f;
        }
    }
    return files;
}

// copy_file() as one of sqwatch's own reads
static int copy_quietly(sqwatch_config *config, const dir_entry *dir, const char *io_path,
                        const char *cached, const char *path) {
    own_reads(config, dir, 1);
    int result = copy_file(io_path, cached, path);
    own_reads(config, dir, 0);
    return result;
}

// Copy every watched file into the cache at startup, overwriting what is
// there. Each file is opened beneath its root and read through that descriptor
void cache_watched_files(sqwatch_config *config) {
    size_t count;
    file_entry **files = file_list(config, &count);
    if (!files && config->files.count) {
        fprintf(stderr, RED "+ Out of memory, not caching the watched files\n" RESET);
    }
    for (size_t n = 0; n < count; n++) {
        stop_if_signalled();
        file_entry *f = files[n];
        // One entry per inode: the names of a file with hard links share it
        if (!f->inode || f->inode->names[0] != f) {
            continue;
        }
        char path[PATH_MAX];
        if (!file_path(config, f, path, sizeof(path))) {
            continue;
        }
        int fd = open_file(config, f);
        if (fd == -1) {
            fprintf(stderr, RED "+ Not caching %s: %s\n" RESET, shown_name(path),
                    errno ? strerror(errno) : "no longer a regular file");
            continue;
        }

        // Every file gets an entry of its own, written now
        char io_path[FD_PATH_LEN];
        inode_node *node = f->inode;
        if (node->cached) {
            unlink_cache_file(node->cached);
            free(node->cached);
        }
        node->cached = cache_new_entry(cache_dir);
        if (node->cached &&
            copy_quietly(config, f->dir, fd_path(fd, io_path, sizeof(io_path)), node->cached,
                         path) == 0 && config->verbose) {
            printf(DARK_GREY "+ Cached: %s\n" RESET, shown_name(path));
        }
        close(fd);
    }
    free(files);
}

// The grace a command gets to end after the stop signal on a restart; on
// exit cleanup() gives it 5 s
#define RESTART_GRACE_MS 2000

// Stop the process group of the previously started command, if any: the stop
// signal (-s, TERM by default), and KILL to what is left after
// RESTART_GRACE_MS. A signal to sqwatch meanwhile ends the wait through
// cleanup()
// A pidfd of the command started last, polled while a -w rerun waits for it
// to end; -1 if none
static int command_pidfd = -1;

static void forget_command_pidfd(void) {
    if (command_pidfd >= 0) {
        close(command_pidfd);
        command_pidfd = -1;
    }
}

static void stop_command(void) {
    forget_command_pidfd();
    if (g_last_pid > 0) {
        killpg(g_last_pid, stop_signal ? stop_signal : SIGTERM);
        for (int waited = 0;; waited += 10) {
            while (waitpid(-g_last_pid, NULL, WNOHANG) > 0) {
            }
            if (kill(-g_last_pid, 0) != 0) {
                break;
            }
            if (waited >= RESTART_GRACE_MS) {
                killpg(g_last_pid, SIGKILL);
                while (waitpid(-g_last_pid, NULL, 0) > 0) {
                }
                break;
            }
            struct timespec step = {0, 10000000};
            nanosleep(&step, NULL);
            stop_if_signalled();
        }
        g_last_pid = 0;
    }
    // As a subreaper sqwatch also inherits what an earlier command left
    // running in a session of its own; reap those that have ended
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

// Run the user's command in its own process group without waiting for it.
// The change that started it is in its environment, never in the command
// string: SQWATCH_PATH, the path as it is, and SQWATCH_EVENT
static void start_command(const char *command, const char *path, const char *event) {
    if (command != NULL) {
        // Hold SIGTERM/SIGINT/SIGHUP across fork. sqwatch keeps them blocked
        // and reads them from a signalfd; the child must get them as usual,
        // and SIGPIPE too, which sqwatch ignores
        sigset_t block, prev;
        sigemptyset(&block);
        sigaddset(&block, SIGTERM);
        sigaddset(&block, SIGINT);
        sigaddset(&block, SIGHUP);
        sigprocmask(SIG_BLOCK, &block, &prev);

        // Nothing sqwatch has buffered may be written by the child as well
        fflush(stdout);
        fflush(stderr);
        g_last_pid = fork();
        if (g_last_pid == -1) {
            // Out of processes for now: this run is skipped, the watch goes on
            fprintf(stderr, RED "+ Could not start the command: %s; it runs again on the next change\n" RESET,
                    strerror(errno));
            g_last_pid = 0;
            sigprocmask(SIG_SETMASK, &prev, NULL);
            return;
        }

        if (g_last_pid == 0) {
            // Child process
            signal(SIGTERM, SIG_DFL);
            signal(SIGINT, SIG_DFL);
            signal(SIGHUP, SIG_DFL);
            signal(SIGPIPE, SIG_DFL);
            sigprocmask(SIG_UNBLOCK, &block, NULL);
            setpgid(0, 0);  // Create new process group
            setvbuf(stdout, NULL, _IONBF, 0);
            setvbuf(stderr, NULL, _IONBF, 0);
            setenv("SQWATCH_PATH", path ? path : "", 1);
            setenv("SQWATCH_EVENT", event ? event : "", 1);
            char *const args[] = {"/bin/sh", "-c", (char *)command, NULL};
            execve("/bin/sh", args, environ);
            perror("execve");
            exit(EXIT_FAILURE);
        }

        // Also set the group from the parent so a stop right after the
        // start cannot miss it; fails harmlessly once the child has exec'd
        setpgid(g_last_pid, g_last_pid);
        sigprocmask(SIG_SETMASK, &prev, NULL);
        forget_command_pidfd();
        command_pidfd = (int)syscall(SYS_pidfd_open, g_last_pid, 0);
    }
}

// What handle_events() keeps between events. Times are in ms of
// CLOCK_MONOTONIC, so that a change of the wall clock does not open or close
// a debounce window
typedef struct {
    int inotify_fd;
    sqwatch_config *config;
    long long now;
    long long window;        // The debounce time
    long long command_run;   // When the command was last started; 0 if never
    int command_wanted;      // A run was asked for while handling events
    int command_due;         // A run is to be made when the window closes
    int rerun;               // -w: a run waits for the running one to end
    char *command_path;      // The latest change a run was asked for: what
    const char *command_event;  // the run gets as SQWATCH_PATH and _EVENT
    long long last_rescan;   // When the tree was last walked after lost events
    int rescan_due;          // Events were lost since: walk again when due
} event_loop;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 1;
}

// Ask for the command to be started again for a change to path, event (see
// event_name()). The requests made while a buffer of events is handled come
// to one run, made by flush_command() once the buffer is done; the run gets
// the latest of them
static void run_command(event_loop *loop, const char *path, const char *event) {
    if (loop->config->perm) {
        return;  // With -p the command only decides permission events
    }
    if ((loop->command_wanted || loop->command_due || loop->rerun) && loop->command_event &&
        strcmp(loop->command_event, "overflow") == 0) {
        return;  // A run for lost events stands for every change since
    }
    char *copy = strdup(path);
    if (copy) {
        free(loop->command_path);
        loop->command_path = copy;
        loop->command_event = event;
    }
    loop->command_wanted = 1;
}

// Whether the command started last is still running: its first process,
// the shell, has not exited
static int command_running(void) {
    if (g_last_pid > 0 && waitpid(g_last_pid, NULL, WNOHANG) == 0) {
        return 1;
    }
    forget_command_pidfd();
    return 0;
}

// Make the run asked for. Runs are coalesced: inside the debounce window of
// the last run, one more is made when the window closes (see run_due()).
// With -w a command still running is not stopped: one more run is made once
// it has exited, however many changes come meanwhile
static void flush_command(event_loop *loop) {
    if (!loop->command_wanted) {
        return;
    }
    loop->command_wanted = 0;
    if (loop->command_run && loop->now - loop->command_run < loop->window) {
        loop->command_due = 1;
        return;
    }
    if (loop->config->wait && command_running()) {
        loop->rerun = 1;
        return;
    }
    loop->rerun = 0;
    stop_command();
    start_command(loop->config->command, loop->command_path, loop->command_event);
    loop->command_run = loop->now;
    loop->command_due = 0;
}

// The name of an event, as the command gets it in SQWATCH_EVENT
static const char *event_name(uint32_t mask) {
    return mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_IGNORED) ? "modify" :
           mask & IN_CREATE ? "create" :
           mask & IN_DELETE ? "delete" :
           mask & IN_MOVE ? "move" :
           mask & IN_ATTRIB ? "attrib" :
           mask & IN_OPEN ? "open" :
           mask & IN_ACCESS ? "access" : "other";
}

static const char *describe(uint32_t mask) {
    return mask & IN_MODIFY ? "Modified" :
           mask & IN_CREATE ? "Created" :
           mask & IN_DELETE ? "Deleted" :
           mask & IN_MOVED_FROM ? "Moved from" :
           mask & IN_MOVED_TO ? "Moved to" :
           mask & IN_CLOSE_WRITE ? "Modified" :
           mask & IN_CLOSE_NOWRITE ? "Closed" :
           mask & IN_OPEN ? "Opened" :
           mask & IN_ATTRIB ? "Attributes" :
           mask & IN_ACCESS ? "Accessed" :
           mask & IN_DELETE_SELF ? "Self deleted" :
           mask & IN_MOVE_SELF ? "Self moved" :
           mask & IN_UNMOUNT ? "Unmounted" :
           mask & IN_Q_OVERFLOW ? "Queue overflow" :
           mask & IN_IGNORED ? "Watch removed" : "Unknown";
}

// Note that the file f has events deferred: mask
static void defer(sqwatch_config *config, file_entry *f, uint32_t mask) {
    if (!f->pending_at) {
        if (push_ptr((void ***)&config->pending, &config->pending_count, &config->pending_size,
                     f) != 0) {
            fprintf(stderr, RED "+ Out of memory, a change may not be shown\n" RESET);
            return;
        }
        f->pending_at = config->pending_count;
    }
    f->pending |= mask;
}

// The file f changed. Say so unless quiet, run the command and diff the file.
// Each file has a debounce window of its own: a change inside it, unless
// forced, is deferred to when it closes, and then handled with any others that
// came meanwhile, if the file changed since (see run_due()). A diff is made
// for a modification; mask IN_IGNORED stands for a file found changed without
// an event of its own
static void fire_file_fd(event_loop *loop, file_entry *f, uint32_t mask, int quiet, int force,
                         int file_fd);

static void fire_file(event_loop *loop, file_entry *f, uint32_t mask, int quiet, int force) {
    fire_file_fd(loop, f, mask, quiet, force, -1);
}

// fire_file(), on the file open as file_fd (an O_PATH descriptor, which this
// closes) if it is not -1, instead of the one f names
static void fire_file_fd(event_loop *loop, file_entry *f, uint32_t mask, int quiet, int force,
                         int file_fd) {
    sqwatch_config *config = loop->config;
    if (!force && f->last_fire && loop->now - f->last_fire < loop->window) {
        defer(config, f, mask);
        if (file_fd != -1) {
            close(file_fd);
        }
        return;
    }
    char path[PATH_MAX];
    if (!file_path(config, f, path, sizeof(path))) {
        if (file_fd != -1) {
            close(file_fd);
        }
        return;
    }
    mask |= f->pending;
    if (f->pending_at) {
        file_entry *last = config->pending[--config->pending_count];
        config->pending[f->pending_at - 1] = last;
        last->pending_at = f->pending_at;
        f->pending_at = 0;
    }
    f->pending = 0;
    f->last_fire = loop->now;
    int fd = file_fd != -1 ? file_fd : open_file(config, f);
    int gone = fd == -1 && errno == ENOENT;
    char io_path[FD_PATH_LEN];
    struct stat st;
    // What the file was like when a write to it was handled: the events
    // that come after it and belong to it (a close after the write) leave
    // nothing new to show (see run_due())
    if (fd != -1 && (mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_IGNORED)) && fstat(fd, &st) == 0) {
        f->fired_ctime = st.st_ctim;
        f->fired_size = st.st_size;
    }
    if (!quiet || (mask & ~IN_IGNORED)) {
        printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, shown_name(path), describe(mask));
    }
    run_command(loop, path, event_name(mask));

    if (fd != -1 && cache_dir && config->diff_enabled && (mask & (IN_MODIFY | IN_IGNORED))) {
        stop_if_signalled();
        // A file without an entry (its copy failed) gets one now; run_diff()
        // then reports it as new
        if (f->inode && !f->inode->cached) {
            f->inode->cached = cache_new_entry(cache_dir);
        }
        if (cache_of(f)) {
            fd_path(fd, io_path, sizeof(io_path));
            own_reads(config, f->dir, 1);
            run_diff(path, io_path, cache_of(f), "Modified",
                     1, // diff is always verbose
                     config->log_file);
            own_reads(config, f->dir, 0);
        }
    }
    if (fd != -1) {
        close(fd);
    }
    if (gone && cache_of(f) && (mask & (IN_MODIFY | IN_IGNORED))) {
        // Gone from its name before the change could be diffed: kept until
        // the event that says where it went. A file moved out takes the
        // change along, to be diffed if it comes back (see take_departed())
        defer(config, f, mask & (IN_MODIFY | IN_IGNORED));
    }
}

// After lost events the tree is walked again (see rescan()), at most once in
// this many ms
#define RESCAN_MS 1000
static void rescan(event_loop *loop);

// Handle the deferred events whose debounce window has closed, and the
// deferred command run. Returns the ms until the next of them is due, or -1
// if none is
static int run_due(event_loop *loop) {
    sqwatch_config *config = loop->config;
    loop->now = now_ms();
    if (loop->rescan_due) {
        if (loop->now - loop->last_rescan >= RESCAN_MS) {
            rescan(loop);  // The walk put off after lost events
            loop->now = now_ms();
        }
    }
    long long next = departed_expire(0);
    if (next >= 0) {
        next += loop->now;
    }
    if (loop->rescan_due) {
        long long due = loop->last_rescan + RESCAN_MS;
        next = next < 0 || due < next ? due : next;
    }
    for (size_t i = 0; i < config->pending_count;) {
        file_entry *f = config->pending[i];
        long long due = f->last_fire + loop->window;
        if (due > loop->now) {
            next = next < 0 || due < next ? due : next;
            i++;
            continue;
        }
        int fd = open_file(config, f);
        struct stat st;
        if (fd == -1 && errno == ENOENT) {
            // Gone from its name: its event, still to come, says where to
            f->last_fire = loop->now;
            next = next < 0 || loop->now + loop->window < next ? loop->now + loop->window : next;
            i++;
            continue;
        }
        // Events that came after the write was handled but belong to it (a
        // close after the write) leave nothing new to show. A write whose
        // file looks the same (a change time is coarse) is compared with
        // the cache; without one it is handled. Other events are handled
        int same = fd == -1 || (fstat(fd, &st) == 0 && st.st_size == f->fired_size &&
                                st.st_ctim.tv_sec == f->fired_ctime.tv_sec &&
                                st.st_ctim.tv_nsec == f->fired_ctime.tv_nsec);
        if (same && fd != -1 && (f->pending & ~(IN_MODIFY | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE))) {
            same = 0;
        } else if (same && fd != -1 && (f->pending & IN_MODIFY)) {
            if (config->diff_enabled && cache_of(f)) {
                char io_path[FD_PATH_LEN];
                fd_path(fd, io_path, sizeof(io_path));
                own_reads(config, f->dir, 1);
                same = !cache_differs(io_path, cache_of(f));
                own_reads(config, f->dir, 0);
            } else {
                same = 0;
            }
        }
        if (fd != -1) {
            close(fd);
        }
        if (same) {
            config->pending[i] = config->pending[--config->pending_count];
            config->pending[i]->pending_at = i + 1;
            f->pending_at = 0;
            f->pending = 0;
            continue;
        }
        fire_file(loop, f, f->pending, 0, 1);  // takes f out of the list
    }
    if (loop->rerun && !command_running()) {
        loop->command_wanted = 1;
    }
    flush_command(loop);
    if (loop->command_due) {
        long long due = loop->command_run + loop->window;
        if (due <= loop->now) {
            loop->command_due = 0;
            loop->command_run = 0;
            loop->command_wanted = 1;
            flush_command(loop);
        } else {
            next = next < 0 || due < next ? due : next;
        }
    }
    if (loop->rerun && command_pidfd < 0) {
        // No pidfd to poll for the end of the command: look every 50 ms
        next = next < 0 || loop->now + 50 < next ? loop->now + 50 : next;
    }
    if (next < 0) {
        return -1;
    }
    long long wait = next - loop->now;
    return wait > 60000 ? 60000 : wait < 0 ? 0 : (int)wait;
}

// Whether name in the directory dir_fd is sqwatch's own log file (or where
// it is written, after a rotation) or cache directory
static int is_own_file(int dir_fd, const char *name) {
    if (is_log_name(dir_fd, name)) {
        return 1;
    }
    int fd = dir_fd == -1 ? -1 : openat(dir_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    int own = fd != -1 && (is_log_file(fd) || is_cache_dir(fd));
    if (fd != -1) {
        close(fd);
    }
    return own;
}

// Whether dir watches name: every name of a walked directory, only the -f
// names of a directory watched for -f files
static int dir_watches_name(const dir_entry *dir, const char *name) {
    if (dir->full) {
        return 1;
    }
    for (int i = 0; i < dir->only_count; i++) {
        if (strcmp(dir->only[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

// The root of the entry name in dir: a -f file's own root, else dir's
static int root_of(const sqwatch_config *config, const dir_entry *dir, const char *name) {
    if (!dir->full) {
        for (int r = 0; r < config->root_count; r++) {
            if (config->roots[r].rel && strcmp(config->roots[r].rel, name) == 0 &&
                strcmp(config->roots[r].path, dir->path) == 0) {
                return r;
            }
        }
    }
    return dir->root;
}

// The entry `name` of dir came into the tree (created, or moved in from
// outside). A directory is walked, a file watched and cached. A file that
// replaces one watched under that name keeps that name's cache entry and is
// diffed against it
static void entry_arrived(event_loop *loop, dir_entry *dir, int dir_fd, const char *name,
                          const char *path) {
    sqwatch_config *config = loop->config;
    struct stat st;
    if (dir_fd == -1 || fstatat(dir_fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return;
    }
    if (S_ISLNK(st.st_mode)) {
        if (config->verbose) {
            printf(DARK_GREY "+ Skipping symlink %s\n" RESET, shown_name(path));
        }
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        if (dir->full) {
            add_watches_walk(config, dir, dir_fd, name, path, dir->root, 2);
        }
        return;
    }
    if (!S_ISREG(st.st_mode)) {
        return;
    }
    file_entry *f = file_find(config, dir, name);
    if (f) {
        // Replaced: the cache entry holds what the name showed before
        file_set_inode(config, f, st.st_dev, st.st_ino, 1);
        f->seen = config->scan;
        mark_changed(config, f, config->creating ? CHANGED_CREATED : CHANGED_TAKEOVER);
        return;
    }
    watch_file(config, dir, dir_fd, name, path, root_of(config, dir, name), 2);
}

// The entry `name` of dir left it (removed, or moved out of the tree)
static void entry_left(sqwatch_config *config, dir_entry *dir, const char *name, int moved) {
    dir_entry *sub = dir_child(config, dir, name);
    if (sub) {
        dir_drop(config, sub, 0);
        return;
    }
    file_entry *f = file_find(config, dir, name);
    if (!f) {
        return;
    }
    if (config->verbose) {
        char path[PATH_MAX];
        printf(DARK_GREY "+ File no longer exists: %s\n" RESET,
               shown_name(file_path(config, f, path, sizeof(path)) ?: name));
    }
    if (moved) {
        // An editor may make a new file under the name in a moment, or the
        // file may come back
        departed_add(dir, name, NULL, f,
                     f->inode && f->inode->count == 1 && f->inode->cached ?
                         take_history(config, f) : NULL);
    }
    file_free(config, f);
}

// The entry from_name of from was renamed to to_name in to, both watched
// directories. A file keeps its cache entry and its events; one that
// replaces a watched file there is diffed against the cache entry of that
// name, which keeps it. A directory keeps its watches, its files and their
// caches; only the paths beneath it change
static void entry_renamed(event_loop *loop, dir_entry *from, const char *from_name,
                          dir_entry *to, int to_fd, const char *to_name, const char *to_path) {
    sqwatch_config *config = loop->config;
    dir_entry *sub = dir_child(config, from, from_name);
    if (sub) {
        if (!to->full || is_ignored(config, to->root, to_path)) {
            dir_drop(config, sub, 0);
        } else if (dir_reparent(config, sub, to, to_name) == 0) {
            dir_repath(sub, to_path);
        } else {
            dir_drop(config, sub, 0);
        }
        return;
    }
    file_entry *f = file_find(config, from, from_name);
    if (!f) {
        // Not watched where it was (ignored, or a -f directory's other
        // name): as if it came from outside
        if (dir_watches_name(to, to_name) && !is_ignored(config, to->root, to_path) &&
            !is_own_file(to_fd, to_name)) {
            entry_arrived(loop, to, to_fd, to_name, to_path);
        }
        return;
    }
    if (!dir_watches_name(to, to_name) || is_ignored(config, root_of(config, to, to_name), to_path)) {
        entry_left(config, from, from_name, 1);
        return;
    }
    file_entry *there = file_find(config, to, to_name);
    if (there) {
        // Its own changes not handled yet are handled first, against its own
        // cache entry. Then the name keeps its history; the file that moved
        // there is diffed against it
        if (f->pending) {
            fire_file_fd(loop, f, 0, 0, 1, to_fd == -1 ? -1 : open_file_at(to_fd, to_name));
        }
        dev_t dev = f->inode ? f->inode->dev : 0;
        ino_t ino = f->inode ? f->inode->ino : 0;
        file_free(config, f);
        if (dev || ino) {
            file_set_inode(config, there, dev, ino, 1);
        }
        mark_changed(config, there, CHANGED_TAKEOVER);
        return;
    }
    if (file_rename(config, f, to, to_name) == 0) {
        f->root = root_of(config, to, to_name);
        departed_add(from, from_name, f, NULL, NULL);
    }
}

// An event on the watch of a directory dir: about an entry in it, named, or
// about dir itself. Entries that come in are watched (and cached, see
// watch_file()), those that go are dropped, renames keep what was known. next
// is the event after this one in the buffer, if any: a rename is two events
// with the same cookie. Returns 1 if next was handled here as well
static int on_dir_event(event_loop *loop, dir_entry *dir, const struct inotify_event *event,
                        const struct inotify_event *next) {
    sqwatch_config *config = loop->config;
    char full_path[PATH_MAX];

    if (event->len == 0) {
        if (event->mask & IN_IGNORED) {
            dir_drop(config, dir, 1);  // Gone, and with it all beneath it
        } else if ((event->mask & (IN_MOVE_SELF | IN_DELETE_SELF)) && !dir->full) {
            // The directory of a -f file was moved or removed: look for the
            // file where its path leads now
            for (int r = 0; r < config->root_count; r++) {
                watch_root *root = &config->roots[r];
                if (root->rel && strcmp(root->path, dir->path) == 0 && reopen_file_root(root)) {
                    file_entry *old = file_find(config, dir, root->rel);
                    char *history = old ? take_history(config, old) : NULL;
                    if (old) {
                        file_free(config, old);
                    }
                    watch_file_root(config, r, 1);
                    dir_entry *now = dir_find(config, add_watch_fd(config->inotify_fd, root->fd,
                                                                   dir_watch_mask(config->flags)));
                    file_entry *f = now ? file_find(config, now, root->rel) : NULL;
                    if (f && give_history(f, history)) {
                        mark_changed(config, f, CHANGED_TAKEOVER);
                    } else if (!f && history) {
                        unlink_cache_file(history);
                        free(history);
                    }
                }
            }
        }
        return 0;  // Reads of the directory itself are not reported
    }
    const char *name = event->name;
    if (!dir_watches_name(dir, name)) {
        return 0;
    }
    if (snprintf(full_path, sizeof(full_path), "%s/%s", dir->path, name) >= (int)sizeof(full_path)) {
        fprintf(stderr, RED "+ Path too long, skipping event\n" RESET);
        return 0;
    }
    int root = root_of(config, dir, name);
    const char *shown = config->roots[root].rel ? config->roots[root].shown : full_path;
    uint32_t mask = event->mask;
    int dir_fd = open_dir(config, dir);
    int consumed = 0;

    // Nothing about an ignored entry, or sqwatch's own log and cache, is
    // shown, and it is never watched
    if (is_ignored(config, root, full_path) ||
        (!(mask & (IN_DELETE | IN_MOVED_FROM)) && is_own_file(dir_fd, name))) {
        if ((mask & IN_MOVED_FROM) && next && (next->mask & IN_MOVED_TO) &&
            next->cookie == event->cookie) {
            // Moved from an ignored name to a watched one: it arrives there
            dir_entry *to = dir_find(config, next->wd);
            char to_path[PATH_MAX];
            if (to && next->len && dir_watches_name(to, next->name) &&
                snprintf(to_path, sizeof(to_path), "%s/%s", to->path, next->name) <
                    (int)sizeof(to_path)) {
                consumed = 1;
                int to_fd = open_dir(config, to);
                if (!is_ignored(config, to->root, to_path) && !is_own_file(to_fd, next->name)) {
                    entry_arrived(loop, to, to_fd, next->name, to_path);
                    if (config->flags & IN_MOVED_TO) {
                        printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, shown_name(to_path),
                               describe(IN_MOVED_TO));
                        run_command(loop, to_path, event_name(IN_MOVED_TO));
                    }
                }
                if (to_fd != -1) {
                    close(to_fd);
                }
            }
        }
        if (dir_fd != -1) {
            close(dir_fd);
        }
        return consumed;
    }

    if (mask & (IN_CREATE | IN_MOVED_TO)) {
        config->creating = (mask & IN_CREATE) != 0;
        entry_arrived(loop, dir, dir_fd, name, full_path);
        config->creating = 0;
        file_entry *f = (mask & IN_CREATE) ? file_find(config, dir, name) : NULL;
        if (f) {
            f->fresh = 1;  // Made empty: its close is no change until it is written
        }
    } else if (mask & IN_DELETE) {
        if (!(mask & IN_ISDIR)) {
            entry_left(config, dir, name, 0);
        }
        // A directory goes with the IN_IGNORED of its own watch
    } else if (mask & IN_MOVED_FROM) {
        dir_entry *to = next && (next->mask & IN_MOVED_TO) && next->cookie == event->cookie &&
                        next->len ? dir_find(config, next->wd) : NULL;
        char to_path[PATH_MAX];
        if (to && snprintf(to_path, sizeof(to_path), "%s/%s", to->path, next->name) <
                      (int)sizeof(to_path)) {
            consumed = 1;
            int to_fd = to == dir ? dup(dir_fd) : open_dir(config, to);
            entry_renamed(loop, dir, name, to, to_fd, next->name, to_path);
            if (to_fd != -1) {
                close(to_fd);
            }
        } else {
            entry_left(config, dir, name, 1);
        }
    } else if (!(mask & IN_ISDIR)) {
        // What happened to the file: written, read, attributes
        file_entry *f = file_find(config, dir, name);
        if (f && (mask & IN_MODIFY)) {
            f->fresh = 0;
        } else if (f && f->fresh && (mask & IN_CLOSE_WRITE)) {
            mask &= ~IN_CLOSE_WRITE;  // A file made and closed unwritten, as by touch
        }
        if (!f && (mask & config->flags)) {
            f = watch_file(config, dir, dir_fd, name, full_path, root, 1);
            if ((mask & (IN_MODIFY | IN_CLOSE_WRITE)) == IN_CLOSE_WRITE) {
                // Closed after writes not seen here, as the log file
                // sqwatch closes once it was rotated: nothing to compare with
                mask &= ~IN_CLOSE_WRITE;
            }
        }
        if (f && (mask & config->flags)) {
            fire_file(loop, f, mask, 0, 0);
        }
    }

    // Only the events asked for run the command. Each of them is shown;
    // command runs are coalesced (see run_command())
    uint32_t asked = mask & config->flags & (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO);
    if (asked) {
        printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, shown_name(shown), describe(asked));
        run_command(loop, shown, event_name(asked));
    }
    if (consumed && (config->flags & IN_MOVED_TO)) {
        dir_entry *to = dir_find(config, next->wd);
        char to_path[PATH_MAX];
        if (to && snprintf(to_path, sizeof(to_path), "%s/%s", to->path, next->name) <
                      (int)sizeof(to_path)) {
            printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, shown_name(to_path),
                   describe(IN_MOVED_TO));
            run_command(loop, to_path, event_name(IN_MOVED_TO));
        }
    }
    if (dir_fd != -1) {
        close(dir_fd);
    }
    return consumed;
}

static void diff_changed(event_loop *loop);

// Events were lost: walk every root again. New files and directories are
// watched and cached, and reported as created; what was not found again is
// dropped, and reported as deleted; every file whose content differs from its
// cache entry is diffed. A file whose size and times are still those its
// cache entry was made from is not read. The command is run once, for the
// lost events
static void rescan(event_loop *loop) {
    sqwatch_config *config = loop->config;
    loop->last_rescan = now_ms();
    loop->rescan_due = 0;
    config->scan++;
    config->rescanning = 1;
    departed_expire(1);
    for (int r = 0; r < config->root_count; r++) {
        watch_root *root = &config->roots[r];
        if (root->rel) {
            reopen_file_root(root);
            watch_file_root(config, r, 1);
        } else {
            add_watches_walk(config, NULL, root->fd, ".", root->path, r, 1);
        }
    }

    // What was not found again: files first, then whole directories
    size_t count, steps = 0;
    file_entry **files = file_list(config, &count);
    for (size_t i = 0; i < count; i++) {
        if ((++steps & 255) == 0) {
            stop_if_signalled();
        }
        if (files[i]->seen != config->scan) {
            char path[PATH_MAX];
            if (file_path(config, files[i], path, sizeof(path))) {
                printf(CYAN "+ Trigger on %s: [ %s ] (found by the walk after lost events)\n" RESET,
                       shown_name(path), describe(IN_DELETE));
            }
            file_free(config, files[i]);
            files[i] = NULL;
        }
    }
    free(files);
    int *stale = NULL;
    size_t stale_count = 0, stale_size = 0;
    for (size_t b = 0; b < config->dirs.size; b++) {
        for (dir_entry *d = config->dirs.buckets[b]; d; d = d->next) {
            if (d->seen != config->scan && stale_count == stale_size) {
                size_t new_size = stale_size ? stale_size * 2 : 16;
                int *grown = realloc(stale, new_size * sizeof(*grown));
                if (!grown) {
                    break;
                }
                stale = grown;
                stale_size = new_size;
            }
            if (d->seen != config->scan) {
                stale[stale_count++] = d->wd;
            }
        }
    }
    // By wd: a stale directory beneath another stale one is gone with it
    for (size_t i = 0; i < stale_count; i++) {
        dir_entry *d = dir_find(config, stale[i]);
        if (d) {
            dir_drop(config, d, 0);
        }
    }
    free(stale);
    config->rescanning = 0;

    if (config->diff_enabled && cache_dir) {
        files = file_list(config, &count);
        for (size_t i = 0; i < count; i++) {
            if ((++steps & 255) == 0) {
                stop_if_signalled();
            }
            file_entry *f = files[i];
            if (!cache_of(f) || f->changed_at || f->inode->names[0] != f) {
                continue;  // One check per inode
            }
            int fd = open_file(config, f);
            char io_path[FD_PATH_LEN];
            int differs = 0;
            if (fd != -1) {
                fd_path(fd, io_path, sizeof(io_path));
                if (!cache_unchanged(io_path, cache_of(f))) {
                    own_reads(config, f->dir, 1);
                    differs = cache_differs(io_path, cache_of(f));
                    own_reads(config, f->dir, 0);
                }
                close(fd);
            }
            if (differs) {
                mark_changed(config, f, CHANGED_RESCAN);
            }
        }
        free(files);
        diff_changed(loop);
    }
    // The run is for the lost events, whatever was found
    run_command(loop, "", "overflow");
}

// Diff the files marked changed. One that took over the cache entry of a name
// it replaced is diffed without a trigger line, as a rearmed watch always
// was; one a rescan found changed is reported
static void diff_changed(event_loop *loop) {
    sqwatch_config *config = loop->config;
    while (config->changed_count > 0) {
        file_entry *f = config->changed[0];
        int why = f->changed;
        config->changed[0] = config->changed[--config->changed_count];
        if (config->changed_count) {
            config->changed[0]->changed_at = 1;
        }
        f->changed_at = 0;
        f->changed = 0;
        int fd = open_file(config, f);
        struct stat st;
        if (fd == -1) {
            continue;
        }
        // A file just created may not be written yet: the write, which its
        // directory's watch now sees, is diffed then. A file that came back
        // without events of its own is diffed only if it differs
        int unwritten = why == CHANGED_CREATED && fstat(fd, &st) == 0 && st.st_size == 0;
        if (why == CHANGED_RETURNED && !f->pending) {
            char io_path[FD_PATH_LEN];
            fd_path(fd, io_path, sizeof(io_path));
            own_reads(config, f->dir, 1);
            unwritten = !config->diff_enabled || !cache_of(f) ||
                        !cache_differs(io_path, cache_of(f));
            own_reads(config, f->dir, 0);
        }
        close(fd);
        if (!unwritten) {
            fire_file(loop, f, why == CHANGED_RESCAN ? IN_MODIFY : IN_IGNORED,
                      why != CHANGED_RESCAN, 1);
        }
    }
}

// The configuration handle_events() and watched_path() work on
static sqwatch_config *events_config;

// The displayed path of the watched regular file dev/ino, or NULL. Good until
// the next call
const char *watched_path(dev_t dev, ino_t ino) {
    static char path[PATH_MAX];
    sqwatch_config *config = events_config;
    if (!config) {
        return NULL;
    }
    inode_node *n = inode_find(config, dev, ino);
    return n && n->count ? file_path(config, n->names[0], path, sizeof(path)) : NULL;
}

// Handle inotify events until SIGINT, SIGTERM or SIGHUP is read from
// signal_fd, and return that signal; SIGTERM if the events cannot be read
int handle_events(int inotify_fd, int signal_fd, sqwatch_config *config) {
    char buffer[BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event))));
    event_loop loop = {inotify_fd, config, 0, config->debounce_ms, 0, 0, 0, 0, NULL, NULL, 0, 0};
    events_config = config;
    int reported_failure = 0;

    while (1) {
        // stdout is polled for an error only: its reader went away. With -p
        // the events the reader thread queued and the end of the command
        // deciding one wake the loop too
        struct pollfd fds[6] = {{inotify_fd, POLLIN, 0}, {signal_fd, POLLIN, 0},
                                {STDOUT_FILENO, 0, 0}, {-1, POLLIN, 0}, {-1, POLLIN, 0},
                                {-1, POLLIN, 0}};
        if (config->watch_failed != reported_failure) {
            // Part of the tree is not watched: like lost events. The message
            // is shown once (see watch_failed()); each new failure runs the
            // command again
            reported_failure = config->watch_failed;
            loop.now = now_ms();
            printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, "(watch limit)", "Queue overflow");
            run_command(&loop, "", "overflow");
            flush_command(&loop);
        }
        int timeout = run_due(&loop);
        // With -w a rerun waits for the command to end: its pidfd says when
        fds[5].fd = loop.rerun ? command_pidfd : -1;
        if (perm_active()) {
            int perm_timeout = perm_work();
            fds[3].fd = perm_wake_fd();
            fds[4].fd = perm_decider_fd();
            if (perm_timeout >= 0 && (timeout < 0 || perm_timeout < timeout)) {
                timeout = perm_timeout;
            }
        }
        stop_if_output_closed();
        if (poll(fds, 6, timeout) == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            return SIGTERM;  // Leave through cleanup() all the same
        }
        if (fds[1].revents & POLLIN) {
            struct signalfd_siginfo info;
            if (read(signal_fd, &info, sizeof(info)) == (ssize_t)sizeof(info)) {
                return (int)info.ssi_signo;
            }
        }
        if (fds[2].revents & (POLLERR | POLLHUP)) {
            stop_if_output_closed();
        }
        if (!(fds[0].revents & POLLIN)) {
            continue;
        }
        ssize_t length = read(inotify_fd, buffer, BUF_LEN);
        if (length == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            perror("inotify read");
            return SIGTERM;
        }

        size_t i = 0;
        int carried = 0;  // The first event in buffer was carried over
        while (i + EVENT_SIZE <= (size_t)length) {
            // A buffer of events can take long to handle: leave between them
            // if a signal is waiting
            stop_if_signalled();
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            size_t at = i;
            i += EVENT_SIZE + event->len;
            struct inotify_event *next = i + EVENT_SIZE <= (size_t)length ?
                (struct inotify_event *)&buffer[i] : NULL;
            size_t size = EVENT_SIZE + event->len;
            if (!next && (event->mask & IN_MOVED_FROM) && !(carried && at == 0) &&
                size <= BUF_LEN / 2) {
                // The other half of a rename may be the first event of the
                // next read: carry this one over to it, waiting a moment
                memmove(buffer, event, size);
                carried = 1;
                struct pollfd more_fd = {inotify_fd, POLLIN, 0};
                ssize_t more = poll(&more_fd, 1, 20) == 1 ?
                    read(inotify_fd, buffer + size, BUF_LEN - size) : -1;
                length = (ssize_t)size + (more > 0 ? more : 0);
                i = 0;
                continue;
            }
            loop.now = now_ms();

            if (event->wd < 0) {
                if (event->mask & IN_Q_OVERFLOW) {
                    fprintf(stderr, RED "+ inotify event queue overflowed; events lost, rescanning\n" RESET);
                    printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, "(lost events)",
                           describe(IN_Q_OVERFLOW));
                    // At most one walk a second, and one more after the last
                    // overflow: a walk is the cost of the whole tree
                    if (loop.last_rescan && loop.now - loop.last_rescan < RESCAN_MS) {
                        loop.rescan_due = 1;
                    } else {
                        rescan(&loop);
                    }
                }
            } else {
                dir_entry *dir = dir_find(config, event->wd);
                if (dir && on_dir_event(&loop, dir, event, next) && next) {
                    i += EVENT_SIZE + next->len;  // The other half of a rename
                }
            }
            diff_changed(&loop);
        }
        flush_command(&loop);
        stop_if_output_closed();
    }
}

void print_usage(void) {
    printf("Usage: sqwatch -d DIR | -f FILE [options]\n"
           "\n"
           "Watch:\n"
           "  -d DIR         Directory to watch, with everything beneath it (repeatable)\n"
           "  -f FILE        File to watch (repeatable), through its directory: it is\n"
           "                 followed when it is deleted and made again\n"
           "  -q EVENTS      Events to react to, separated by commas (default: modify):\n"
           "                   modify   a file was written\n"
           "                   create   a file or directory was created\n"
           "                   delete   a file or directory was deleted\n"
           "                   move     a file or directory was moved or renamed\n"
           "                   attrib   mode, owner or times changed\n"
           "                   open     a file was opened\n"
           "                   access   a file was read\n"
           "                   all      all of the above but open and access\n"
           "                 sqwatch's own reads never count; the command's do\n"
           "  -i PATTERN     Ignore what matches PATTERN (repeatable): not watched, not\n"
           "                 walked, never shown. A PATTERN with a '/' is matched against\n"
           "                 the path below the watched directory, any other against the\n"
           "                 name; for example -i '*.o' -i build/tmp. Always ignored: .git,\n"
           "                 and sqwatch's own log file and cache directory\n"
           "\n"
           "Command:\n"
           "  -c COMMAND     Run COMMAND with /bin/sh -c on each change; a run still going\n"
           "                 is stopped and started again. Without -c sqwatch only shows\n"
           "                 events and diffs (observe mode), with no debounce unless -t.\n"
           "                 COMMAND gets the change in its environment: SQWATCH_PATH,\n"
           "                 the path, and SQWATCH_EVENT: modify, create, delete, move,\n"
           "                 attrib, open, access (overflow, with an empty path, after\n"
           "                 lost events or a failed watch). Use them quoted, as\n"
           "                 \"$SQWATCH_PATH\". When changes come together, one run is made,\n"
           "                 for the latest of them\n"
           "  -w             Wait for a run still going to end instead of stopping it;\n"
           "                 the changes that come meanwhile lead to one more run after it\n"
           "  -s SIGNAL      Signal that stops a run: a name, with or without SIG, or a\n"
           "                 number (default: TERM). What is left of the run gets KILL\n"
           "                 2 s later on a restart, 5 s later when sqwatch exits\n"
           "  -t SECONDS     Debounce time of each file, a decimal number (default: 1,\n"
           "                 or 0 without -c)\n"

           "\n"
           "Intercept (fanotify, needs CAP_SYS_ADMIN):\n"
           "  -p EVENTS      Hold each open, read or exec of the watched files until\n"
           "                 COMMAND (-c) decides: exit status 0 allows it, any other\n"
           "                 denies it (EPERM). EVENTS: open, access, exec, separated by\n"
           "                 commas. COMMAND also gets SQWATCH_PID, the process opening\n"
           "                 the file. One COMMAND runs at a time; sqwatch's own reads\n"
           "                 and COMMAND's own process group are always allowed. Not\n"
           "                 with -q; --diff still shows what is written\n"
           "  -T TIMEOUT     Time COMMAND has to decide: SECONDS (default: 5), then the\n"
           "                 access is allowed and COMMAND killed; deny or SECONDS:deny\n"
           "                 to deny it then instead\n"
           "\n"
           "Diff:\n"
           "  --diff         Show what changed in each file, from a private cache (a file\n"
           "                 over 64 MiB, or past 256 MiB for all, keeps only its size\n"
           "                 and modification time). Each diff stops after 500 lines\n"
           "                 or 1 MiB, with a note of the lines left out\n"
           "  -l FILE        Also write the diffs to FILE (needs --diff)\n"
           "\n"
           "Other:\n"
           "  -v             Verbose output\n"
           "  -h, --help     Show this help\n"
           "\n"
           "Examples:\n"
           "  sqwatch -d src -q modify --diff              # Show diffs of files in src\n"
           "  sqwatch -f config.txt -q all --diff -l changes.log  # Log every change\n"
           "  sqwatch -d src -t 0.5 -c 'make test'         # Run the tests on each change\n");
}
