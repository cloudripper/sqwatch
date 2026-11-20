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

static size_t watch_slot(const watch_table *table, int wd) {
  return ((unsigned)wd * 2654435761u) & (table->size - 1);
}

// The entry of watch descriptor wd, or NULL. An entry pointer is good until
// the next watch is added or dropped
watch_entry *watch_find(watch_table *table, int wd) {
  if (table->size == 0 || wd < 0) {
    return NULL;
  }
  for (size_t s = watch_slot(table, wd);; s = (s + 1) & (table->size - 1)) {
    if (table->slots[s].wd == wd) {
      return &table->slots[s];
    }
    if (table->slots[s].wd < 0) {
      return NULL;
    }
  }
}

// The entry of wd, made empty (no names, no cache entry) if there was none.
// NULL if wd is invalid or memory runs out
watch_entry *watch_add(watch_table *table, int wd) {
  watch_entry *entry = watch_find(table, wd);
  if (entry || wd < 0) {
    return entry;
  }
  if ((table->count + 1) * 4 > table->size * 3) {
    size_t new_size = table->size ? table->size * 2 : 64;
    watch_entry *slots = malloc(new_size * sizeof(*slots));
    if (!slots) {
      return NULL;
    }
    for (size_t s = 0; s < new_size; s++) {
      slots[s].wd = -1;
    }
    watch_table grown = {slots, new_size, table->count};
    for (size_t s = 0; s < table->size; s++) {
      if (table->slots[s].wd >= 0) {
        size_t t = watch_slot(&grown, table->slots[s].wd);
        while (slots[t].wd >= 0) {
          t = (t + 1) & (new_size - 1);
        }
        slots[t] = table->slots[s];
      }
    }
    free(table->slots);
    *table = grown;
  }
  size_t s = watch_slot(table, wd);
  while (table->slots[s].wd >= 0) {
    s = (s + 1) & (table->size - 1);
  }
  table->slots[s] = (watch_entry){.wd = wd};
  table->count++;
  return &table->slots[s];
}

// Free the slot of entry, which has no names left. Entries after it in its
// probe run are moved back, so no slot is left marked deleted
static void watch_remove(watch_table *table, watch_entry *entry) {
  size_t mask = table->size - 1;
  size_t hole = (size_t)(entry - table->slots);
  free(entry->names);
  free(entry->cached);
  for (size_t s = (hole + 1) & mask; table->slots[s].wd >= 0; s = (s + 1) & mask) {
    size_t home = watch_slot(table, table->slots[s].wd);
    // Move it back if its home slot is not between the hole and it
    if (((s - home) & mask) >= ((s - hole) & mask)) {
      table->slots[hole] = table->slots[s];
      hole = s;
    }
  }
  table->slots[hole].wd = -1;
  table->count--;
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

// Open name n of entry beneath its root, without following symlinks, as an
// O_PATH descriptor of a regular file, or -1. A -f file that is not found, or
// whose watch is gone, is looked for once more in what its directory path
// names now, as the directory may have been replaced
static int open_name(sqwatch_config *config, const watch_entry *entry, int n, int gone) {
    watch_root *root = &config->roots[entry->names[n].root];
    const char *rel = rel_path(root, entry->names[n].path);
    int fd = open_beneath(root->fd, rel, O_PATH);
    if (root->rel && (gone || (fd == -1 && (errno == ENOENT || errno == ENOTDIR))) &&
        reopen_file_root(root)) {
        if (fd != -1) {
            close(fd);
        }
        fd = open_beneath(root->fd, rel, O_PATH);
    }
    struct stat st;
    if (fd != -1 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))) {
        close(fd);
        fd = -1;
    }
    return fd;
}

// Whether fd is the inode entry watches
static int is_entry_file(int fd, const watch_entry *entry) {
    struct stat st;
    return fstat(fd, &st) == 0 && st.st_dev == entry->dev && st.st_ino == entry->ino;
}

// Open the file entry watches by the first of its names that leads to it, and
// set *n to that name's index. Returns an O_PATH descriptor, or -1
static int open_entry(sqwatch_config *config, const watch_entry *entry, int *n) {
    for (*n = 0; *n < entry->name_count; (*n)++) {
        int fd = open_name(config, entry, *n, 0);
        if (fd != -1 && is_entry_file(fd, entry)) {
            return fd;
        }
        if (fd != -1) {
            close(fd);
        }
    }
    return -1;
}

static size_t hash_path(const char *path) {
  size_t h = 14695981039346656037u;
  for (const unsigned char *p = (const unsigned char *)path; *p; p++) {
    h = (h ^ *p) * 1099511628211u;
  }
  return h;
}

// The slot of path in the name index, or of the free slot where it would go
static name_slot *name_slot_of(const name_index *index, const char *path, size_t hash) {
  size_t mask = index->size - 1;
  for (size_t s = hash & mask;; s = (s + 1) & mask) {
    name_slot *slot = &index->slots[s];
    if (!slot->path || (slot->hash == hash && strcmp(slot->path, path) == 0)) {
      return slot;
    }
  }
}

// The watch descriptor whose names include path, or -1
static int name_wd(const name_index *index, const char *path) {
  if (index->size == 0) {
    return -1;
  }
  name_slot *slot = name_slot_of(index, path, hash_path(path));
  return slot->path ? slot->wd : -1;
}

// Record that path, a string the caller keeps, names watch wd
static int name_put(name_index *index, const char *path, int wd) {
  if ((index->count + 1) * 4 > index->size * 3) {
    size_t new_size = index->size ? index->size * 2 : 64;
    name_slot *slots = calloc(new_size, sizeof(*slots));
    if (!slots) {
      return -1;
    }
    name_index grown = {slots, new_size, index->count};
    for (size_t s = 0; s < index->size; s++) {
      if (index->slots[s].path) {
        *name_slot_of(&grown, index->slots[s].path, index->slots[s].hash) = index->slots[s];
      }
    }
    free(index->slots);
    *index = grown;
  }
  size_t hash = hash_path(path);
  name_slot *slot = name_slot_of(index, path, hash);
  if (!slot->path) {
    index->count++;
  }
  *slot = (name_slot){path, hash, wd};
  return 0;
}

static void name_del(name_index *index, const char *path) {
  if (index->size == 0) {
    return;
  }
  size_t mask = index->size - 1;
  name_slot *slot = name_slot_of(index, path, hash_path(path));
  if (!slot->path) {
    return;
  }
  size_t hole = (size_t)(slot - index->slots);
  for (size_t s = (hole + 1) & mask; index->slots[s].path; s = (s + 1) & mask) {
    size_t home = index->slots[s].hash & mask;
    if (((s - home) & mask) >= ((s - hole) & mask)) {
      index->slots[hole] = index->slots[s];
      hole = s;
    }
  }
  index->slots[hole].path = NULL;
  index->count--;
}

// Take name n away from entry, keeping the order of the others
static void remove_name(sqwatch_config *config, watch_entry *entry, int n) {
  name_del(&config->names, entry->names[n].path);
  free(entry->names[n].path);
  entry->name_count--;
  memmove(&entry->names[n], &entry->names[n + 1],
          (entry->name_count - n) * sizeof(*entry->names));
}

// Stop watching wd: the kernel watch, unless it is gone already, the cache
// entry and every name of it. shown names the file in a verbose message
static void drop_watch(int inotify_fd, sqwatch_config *config, int wd, int watch_gone,
                       const char *shown) {
  watch_entry *entry = watch_find(&config->watches, wd);
  if (!entry) {
    return;
  }
  if (!watch_gone) {
    inotify_rm_watch(inotify_fd, wd);
  }
  if (entry->cached) {
    if (config->verbose) {
      printf(DARK_GREY "+ Removing cache for: %s\n" RESET,
             shown_name(shown ? shown : entry->name_count ? entry->names[0].path : "?"));
    }
    unlink_cache_file(entry->cached);
  }
  while (entry->name_count > 0) {
    remove_name(config, entry, entry->name_count - 1);
  }
  watch_remove(&config->watches, entry);
}

// Note that the file watched by wd has to be diffed against its cache entry:
// it took over the entry of a name it replaced (CHANGED_TAKEOVER), or a rescan
// found it differs (CHANGED_RESCAN). handle_events() goes through the list
static void mark_changed(sqwatch_config *config, int wd, unsigned char why) {
  watch_entry *entry = watch_find(&config->watches, wd);
  if (!entry || entry->changed) {
    return;
  }
  if (config->changed_count == config->changed_size) {
    size_t new_size = config->changed_size ? config->changed_size * 2 : 16;
    int *grown = realloc(config->changed, new_size * sizeof(*grown));
    if (!grown) {
      fprintf(stderr, RED "+ Out of memory, a change may not be shown\n" RESET);
      return;
    }
    config->changed = grown;
    config->changed_size = new_size;
  }
  config->changed[config->changed_count++] = wd;
  entry->changed = why;
}

// path is not a name of what it was watched as any more: it was removed,
// moved away or replaced. A watch with no name left in the tree is dropped,
// one with another name (a hard link) is kept
static void drop_name(int inotify_fd, sqwatch_config *config, const char *path) {
  int wd = name_wd(&config->names, path);
  watch_entry *entry = watch_find(&config->watches, wd);
  if (!entry) {
    return;
  }
  for (int n = 0; n < entry->name_count; n++) {
    if (strcmp(entry->names[n].path, path) == 0) {
      if (config->verbose && !entry->is_dir) {
        printf(DARK_GREY "+ File no longer exists: %s\n" RESET, shown_name(path));
      }
      remove_name(config, entry, n);
      break;
    }
  }
  if (entry->name_count == 0) {
    drop_watch(inotify_fd, config, wd, 0, path);
  }
}

// drop_name() for path and for every name beneath it
static void drop_tree(int inotify_fd, sqwatch_config *config, const char *path) {
  size_t len = strlen(path);
  char **below = NULL;
  size_t count = 0, size = 0;
  for (size_t s = 0; s < config->watches.size; s++) {
    const watch_entry *entry = &config->watches.slots[s];
    for (int n = 0; entry->wd >= 0 && n < entry->name_count; n++) {
      const char *name = entry->names[n].path;
      if (strncmp(name, path, len) != 0 || name[len] != '/') {
        continue;
      }
      if (count == size) {
        size_t new_size = size ? size * 2 : 64;
        char **grown = realloc(below, new_size * sizeof(*grown));
        if (!grown) {
          break;
        }
        below = grown;
        size = new_size;
      }
      below[count] = strdup(name);
      if (below[count]) {
        count++;
      }
    }
  }
  for (size_t i = 0; i < count; i++) {
    drop_name(inotify_fd, config, below[i]);
    free(below[i]);
  }
  free(below);
  drop_name(inotify_fd, config, path);
}

// Record that path, in root, names the file or directory fd, watched as wd.
// If path named another file before (it was replaced: renamed over, or moved
// away and made again), this file takes over that file's cache entry, which
// holds what the name showed before, and is marked changed, to be diffed. The
// other file gets a fresh cache entry if it still has a name, and its watch
// is dropped if not. A
// directory has one name, the last it was found by. Returns the entry, or NULL
static watch_entry *attach_name(int inotify_fd, sqwatch_config *config, int wd, int fd,
                                int is_dir, const char *path, int root, int *added) {
  watch_entry *entry = watch_add(&config->watches, wd);
  struct stat st;
  *added = 0;
  if (!entry) {
    fprintf(stderr, RED "+ Out of memory, not watching %s\n" RESET, shown_name(path));
    return NULL;
  }
  if (entry->name_count == 0) {
    if (fstat(fd, &st) == 0) {
      entry->dev = st.st_dev;
      entry->ino = st.st_ino;
    }
    entry->is_dir = is_dir;
  }

  int old = name_wd(&config->names, path);
  if (old == wd) {
    for (int n = 0; n < entry->name_count; n++) {
      if (strcmp(entry->names[n].path, path) == 0) {
        entry->names[n].seen = config->scan;
        entry->names[n].root = root;
      }
    }
    return entry;
  }
  if (old >= 0) {
    watch_entry *before = watch_find(&config->watches, old);
    for (int n = 0; n < before->name_count; n++) {
      if (strcmp(before->names[n].path, path) == 0) {
        remove_name(config, before, n);
        break;
      }
    }
    if (!is_dir && !before->is_dir && before->cached) {
      // The cache entry holds what path showed: it goes with the name. A
      // file still watched under another name gets a fresh copy of its own
      char *fresh = NULL;
      int n;
      int other = open_entry(config, before, &n);
      if (other != -1) {
        char io_path[FD_PATH_LEN];
        create_cache_for_file(before->names[n].path, fd_path(other, io_path, sizeof(io_path)),
                              cache_dir, &fresh, 0);
      }
      if (other != -1) {
        close(other);
      }
      if (entry->cached) {
        unlink_cache_file(entry->cached);
        free(entry->cached);
      }
      entry->cached = before->cached;
      before->cached = fresh;
      mark_changed(config, wd, config->creating ? CHANGED_CREATED : CHANGED_TAKEOVER);
    }
    if (before->name_count == 0) {
      drop_watch(inotify_fd, config, old, 0, path);
      entry = watch_find(&config->watches, wd);
    }
  }
  if (is_dir) {
    while (entry->name_count > 0) {
      remove_name(config, entry, entry->name_count - 1);
    }
  }

  watch_name *names = realloc(entry->names, (entry->name_count + 1) * sizeof(*names));
  char *copy = strdup(path);
  if (names) {
    entry->names = names;
  }
  if (!names || !copy || name_put(&config->names, copy, wd) != 0) {
    free(copy);
    fprintf(stderr, RED "+ Out of memory, not watching %s\n" RESET, shown_name(path));
    if (entry->name_count == 0) {
      drop_watch(inotify_fd, config, wd, 0, path);
    }
    return NULL;
  }
  entry->names[entry->name_count++] = (watch_name){copy, root, config->scan};
  *added = 1;
  return entry;
}

// Watch the regular file `name` in the directory parent_fd; path is its
// displayed path. A file found after startup (at_runtime) is cached here, if
// it has no cache entry yet; at_runtime 2 is a file that was just created or
// moved into the tree
static void watch_file(int inotify_fd, int parent_fd, const char *name, const char *path,
                       int root, uint32_t flags, sqwatch_config *config, int at_runtime) {
    int fd = open_file_at(parent_fd, name);
    int wd = fd == -1 ? -1 : add_watch_fd(inotify_fd, fd, flags);
    int added = 0;
    watch_entry *entry = wd < 0 ? NULL :
        attach_name(inotify_fd, config, wd, fd, 0, path, root, &added);
    if (entry && at_runtime && config->diff_enabled && cache_dir && !entry->cached) {
        char io_path[FD_PATH_LEN];
        create_cache_for_file(path, fd_path(fd, io_path, sizeof(io_path)), cache_dir,
                              &entry->cached, config->verbose);
    }
    if (added && config->verbose) {
        if (at_runtime == 2) {
            printf(CYAN "+ Added watch for new file: %s\n" RESET, shown_name(path));
        } else {
            printf(CYAN "+ Watch set for file %s\n" RESET, shown_name(path));
        }
    }
    if (fd != -1) {
        close(fd);
    }
}

// Watch the directory dir_fd refers to; path is its displayed path
static void watch_dir(int inotify_fd, int dir_fd, const char *path, int root, uint32_t flags,
                      sqwatch_config *config) {
    int wd = add_watch_fd(inotify_fd, dir_fd, flags | DIR_WATCH_EVENTS);
    int added = 0;
    // A directory watched before (walked again, or reached by another name)
    // gets the wd it already has: its entry is updated
    if (wd >= 0 && attach_name(inotify_fd, config, wd, dir_fd, 1, path, root, &added) &&
        added && config->verbose) {
        printf(CYAN "+ Watch set for directory %s\n" RESET, shown_name(path));
    }
}

// A directory the walk is in, from where it started down to the current one
typedef struct {
    char **names;            // Its subdirectories, in readdir order
    size_t count;            // Number of names
    size_t next;             // Index of the next name to look at
    dev_t dev;               // The directory found and watched, to know it
    ino_t ino;               // again when the walk comes back to it
    size_t path_len;         // Length of its displayed path in the path buffer
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
static int read_names(int inotify_fd, int fd, char *path, int root, uint32_t flags,
                      sqwatch_config *config, int at_runtime, walk_level *level) {
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
        if ((++seen & 1023) == 0) {
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
                watch_file(inotify_fd, fd, name, path, root, flags, config, at_runtime);
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
// buffer, watch its files and make it the innermost level, holding its
// subdirectories. Returns 0 if it could not be read; fd is the caller's either
// way
static int enter_dir(int inotify_fd, int fd, char *path, int root, uint32_t flags,
                     sqwatch_config *config, int at_runtime, walk_level **levels,
                     size_t *depth, size_t *size) {
    struct stat st;
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
    watch_dir(inotify_fd, fd, path, root, flags, config);
    walk_level *level = &(*levels)[*depth];
    *level = (walk_level){NULL, 0, 0, st.st_dev, st.st_ino, strlen(path)};
    if (read_names(inotify_fd, fd, path, root, flags, config, at_runtime, level) != 0) {
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

// Add watches for the entry `name` of the directory parent_fd and, if it is a
// directory, for everything below it. path is the entry's displayed path.
// The walk is depth first. The files of a directory are watched while it is
// read, before any of its subdirectories is entered; the recursive walk of
// v0.4.1 took files and subdirectories in readdir order instead.
// It holds one descriptor, of the directory it is in, and keeps the names of
// the subdirectories still to walk of each directory on the way down on the
// heap: there is no recursion and no descriptor held per level, however deep
// the tree. A directory is read in full when the walk enters it, as a readdir
// position cannot be kept without keeping its stream open. Directories are
// entered with openat() relative to the current one and left through "..",
// checked to be the directory entered before; symlinks are never followed, so
// the walk cannot leave the tree it started in. at_runtime is set for an
// entry found after startup: its files are cached here, as
// cache_watched_files() only covers the startup walk; see watch_file()
static void add_watches_walk(int inotify_fd, int parent_fd, const char *name, const char *path,
                             int root, uint32_t flags, sqwatch_config *config, int at_runtime) {
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
        watch_file(inotify_fd, parent_fd, name, path, root, flags, config, at_runtime);
        return;
    }

    // A -f root names one file; if it has been replaced by a directory since it
    // was checked, nothing is watched
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
    if (!enter_dir(inotify_fd, cur, dir_path, root, flags, config, at_runtime, &levels, &depth,
                   &size)) {
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
            watch_file(inotify_fd, cur, entry, dir_path, root, flags, config, at_runtime);
        } else if (S_ISDIR(st.st_mode)) {
            int fd = openat(cur, entry, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd == -1) {
                fprintf(stderr, RED "+ Failed to open directory %s: %s\n" RESET,
                        shown_name(dir_path),
                        strerror(errno));
            } else if (enter_dir(inotify_fd, fd, dir_path, root, flags, config, at_runtime,
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

// Start watching a path named on the command line. This and
// reopen_file_root() are the only places where symlinks are followed: the
// operator's path is trusted, what is found beneath it later is not
void add_watches_recursive(int inotify_fd, const char *path, uint32_t flags,
                           sqwatch_config *config) {
    struct stat path_stat;
    if (stat(path, &path_stat) == -1) {
        fprintf(stderr, RED "+ Failed to stat %s: %s\n" RESET, shown_name(path), strerror(errno));
        return;
    }
    watch_root *root = &config->roots[config->root_count];
    const char *name = ".";
    root->path = NULL;
    root->rel = NULL;
    root->fd = -1;
    root->shown = strdup(path);

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
    if (root->fd == -1 || !root->path || !name || !root->shown) {
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

    config->root_count++;
    add_watches_walk(inotify_fd, root->fd, name, path, config->root_count - 1, flags, config, 0);
}

static int compare_ints(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

// The watch descriptors of every file watch, in increasing order, in an array
// to free; *count is set to their number. NULL if there are none or memory
// runs out
static int *file_watch_list(const watch_table *table, size_t *count) {
    int *wds = table->count ? malloc(table->count * sizeof(*wds)) : NULL;
    *count = 0;
    if (!wds) {
        return NULL;
    }
    for (size_t s = 0; s < table->size; s++) {
        if (table->slots[s].wd >= 0 && !table->slots[s].is_dir) {
            wds[(*count)++] = table->slots[s].wd;
        }
    }
    qsort(wds, *count, sizeof(*wds), compare_ints);
    return wds;
}

// Copy every watched file into the cache at startup, overwriting what is
// there. Each file is opened beneath its root and read through that descriptor
void cache_watched_files(sqwatch_config *config) {
    size_t count;
    int *wds = file_watch_list(&config->watches, &count);
    if (!wds && config->watches.count) {
        fprintf(stderr, RED "+ Out of memory, not caching the watched files\n" RESET);
    }
    for (size_t n = 0; n < count; n++) {
        stop_if_signalled();
        watch_entry *entry = watch_find(&config->watches, wds[n]);
        const char *path = entry->names[0].path;

        const watch_root *root = &config->roots[entry->names[0].root];
        struct stat st;
        int fd = open_beneath(root->fd, rel_path(root, path), O_PATH);
        if (fd == -1) {
            fprintf(stderr, RED "+ Not caching %s: %s\n" RESET,
                    shown_name(path), strerror(errno));
            continue;
        }
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            fprintf(stderr, RED "+ Not caching %s: no longer a regular file\n" RESET,
                    shown_name(path));
            close(fd);
            continue;
        }

        // Every file gets an entry of its own, written now
        char io_path[FD_PATH_LEN];
        if (entry->cached) {
            unlink_cache_file(entry->cached);
            free(entry->cached);
        }
        entry->cached = cache_new_entry(cache_dir);
        if (entry->cached &&
            copy_file(fd_path(fd, io_path, sizeof(io_path)), entry->cached, path) == 0 &&
            config->verbose) {
            printf(DARK_GREY "+ Cached [%d]: %s\n" RESET, wds[n], shown_name(path));
        }
        close(fd);
    }
    free(wds);
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
    // As a subreaper sqwatch also inherits what an earlier command left
    // running in a session of its own; reap those that have ended
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

// Run the user's command in its own process group without waiting for it
static void start_command(const char *command) {
    if (command != NULL) {
        // Hold SIGTERM/SIGINT across fork. sqwatch keeps them blocked and
        // reads them from a signalfd; the child must get them as usual
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
            sigprocmask(SIG_UNBLOCK, &block, NULL);
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

// What handle_events() keeps between events
typedef struct {
    int inotify_fd;
    sqwatch_config *config;
    time_t now;
    time_t last_event;       // Last trigger for a change to a file
    time_t last_create;      // Last trigger for an entry created, removed or moved
} event_loop;

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
           mask & IN_DELETE_SELF ? "Self deleted" :
           mask & IN_MOVE_SELF ? "Self moved" :
           mask & IN_UNMOUNT ? "Unmounted" :
           mask & IN_Q_OVERFLOW ? "Queue overflow" :
           mask & IN_IGNORED ? "Watch removed" : "Unknown";
}

// The file watched by wd changed: it is reached as path, read through
// io_path. Run the command, say so unless quiet, and diff the file, unless
// this falls in the debounce window and is not forced. A diff is made for a
// modification; mask IN_IGNORED stands for a file found changed without an
// event of its own
static void fire_file(event_loop *loop, int wd, const char *path, const char *io_path,
                      uint32_t mask, int quiet, int force) {
    sqwatch_config *config = loop->config;
    if (loop->now - loop->last_event < config->debounce_t && !force) {
        return;
    }
    stop_command();
    if (!quiet) {
        printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, shown_name(path), describe(mask));
    }
    start_command(config->command);

    watch_entry *entry = watch_find(&config->watches, wd);
    if (cache_dir && config->diff_enabled && entry && (mask & (IN_MODIFY | IN_IGNORED))) {
        stop_if_signalled();
        // A file without an entry (its copy failed) gets one now; run_diff()
        // then reports it as new
        if (!entry->cached) {
            entry->cached = cache_new_entry(cache_dir);
        }
        if (entry->cached) {
            run_diff(path, io_path, entry->cached, "Modified",
                     1, // diff is always verbose
                     config->log_file);
        }
    }
    loop->last_event = loop->now;
}

// An event on the watch of a file. It is handled under the first of the
// file's names that still leads to it. A name that leads nowhere now is
// dropped; one that leads to another file (it was replaced, and no event of
// the directory said so: a -f file, or the event was lost) gets that file
// watched, which takes over the cache entry when no name is left here. When
// no name leads to the file any more, its watch is dropped. IN_IGNORED says
// the watch is gone: every name is then looked up again
static void on_file_event(event_loop *loop, int wd, uint32_t mask) {
    sqwatch_config *config = loop->config;
    watch_entry *entry = watch_find(&config->watches, wd);
    int gone = (mask & IN_IGNORED) != 0;
    int found_fd = -1;
    char *found = NULL;

    // The names as they are now: the loop below may take them away
    int count = entry->name_count;
    watch_name *names = malloc(count * sizeof(*names));
    if (!names) {
        fprintf(stderr, RED "+ Out of memory handling an event\n" RESET);
        return;
    }
    for (int n = 0; n < count; n++) {
        names[n] = entry->names[n];
        names[n].path = strdup(entry->names[n].path);
    }

    for (int n = 0; n < count; n++) {
        if (!names[n].path) {
            continue;
        }
        entry = watch_find(&config->watches, wd);
        int k = 0;
        while (entry && k < entry->name_count && strcmp(entry->names[k].path, names[n].path) != 0) {
            k++;
        }
        if (!entry || k == entry->name_count) {
            continue;  // Taken away meanwhile
        }
        int fd = open_name(config, entry, k, gone);
        if (fd == -1) {
            drop_name(loop->inotify_fd, config, names[n].path);
        } else if (!gone && is_entry_file(fd, entry)) {
            if (!found) {
                found = names[n].path;
                names[n].path = NULL;
                found_fd = fd;
                fd = -1;
            }
        } else {
            // Another file has this name now, or this one lost its watch
            int new_wd = add_watch_fd(loop->inotify_fd, fd, config->flags);
            int added;
            watch_entry *now = new_wd < 0 ? NULL :
                attach_name(loop->inotify_fd, config, new_wd, fd, 0, names[n].path, names[n].root,
                            &added);
            if (now && !now->cached && config->diff_enabled && cache_dir) {
                char io_path[FD_PATH_LEN];
                create_cache_for_file(names[n].path, fd_path(fd, io_path, sizeof(io_path)),
                                      cache_dir, &now->cached, config->verbose);
            }
            if (now && config->verbose) {
                printf(DARK_GREY "+ Reapplied watch for %s\n" RESET, shown_name(names[n].path));
            }
            if (!now) {
                drop_name(loop->inotify_fd, config, names[n].path);
            }
        }
        if (fd != -1) {
            close(fd);
        }
    }
    for (int n = 0; n < count; n++) {
        free(names[n].path);
    }
    free(names);

    if (watch_find(&config->watches, wd) && (gone || !found)) {
        // Nothing in the watched trees leads to this file any more
        drop_watch(loop->inotify_fd, config, wd, gone, NULL);
    }
    if (found) {
        char io_path[FD_PATH_LEN];
        fire_file(loop, wd, found, fd_path(found_fd, io_path, sizeof(io_path)), mask, 0, 0);
        close(found_fd);
        free(found);
    }
}

// An event on the watch of a directory: an entry was created, removed or moved
// in or out of it. What comes in is watched (and cached, see watch_file());
// what goes is dropped. The directory itself gone (IN_IGNORED) takes what is
// beneath it along
static void on_dir_event(event_loop *loop, int wd, const struct inotify_event *event,
                         const struct inotify_event *next) {
    sqwatch_config *config = loop->config;
    watch_entry *entry = watch_find(&config->watches, wd);
    char dir_path[PATH_MAX];
    char full_path[PATH_MAX];
    int dir_root = entry->names[0].root;
    snprintf(dir_path, sizeof(dir_path), "%s", entry->names[0].path);

    if (event->mask & IN_IGNORED) {
        drop_tree(loop->inotify_fd, config, dir_path);
        drop_watch(loop->inotify_fd, config, wd, 1, NULL);
        return;
    }
    if (event->len == 0 || !(event->mask & DIR_WATCH_EVENTS)) {
        return;
    }
    if (snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, event->name) >= (int)sizeof(full_path)) {
        fprintf(stderr, RED "+ Path too long, skipping event\n" RESET);
        return;
    }

    uint32_t asked = event->mask & config->flags & DIR_WATCH_EVENTS;
    int exists = 1;
    // A file renamed within the watched trees keeps its old name for now:
    // whatever is made under it next (an editor that moves the file aside to
    // write a new one) takes over its cache entry. The name goes once it is
    // found to lead nowhere. The rename is the next event, with the same
    // cookie
    int renamed = (event->mask & IN_MOVED_FROM) && !(event->mask & IN_ISDIR) && next &&
                  (next->mask & IN_MOVED_TO) && next->cookie == event->cookie;
    if ((event->mask & (IN_DELETE | IN_MOVED_FROM)) && !renamed) {
        if (event->mask & IN_ISDIR) {
            drop_tree(loop->inotify_fd, config, full_path);
        } else {
            drop_name(loop->inotify_fd, config, full_path);
        }
    } else if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
        // Reach the directory from its root without following symlinks
        // and look at the new entry relative to that descriptor
        const watch_root *root = &config->roots[dir_root];
        int dir_fd = open_beneath(root->fd, rel_path(root, dir_path), O_PATH | O_DIRECTORY);
        struct stat path_stat;
        exists = dir_fd != -1 && fstatat(dir_fd, event->name, &path_stat, AT_SYMLINK_NOFOLLOW) == 0;
        if (exists && S_ISLNK(path_stat.st_mode)) {
            if (config->verbose) {
                printf(DARK_GREY "+ Skipping symlink %s\n" RESET, shown_name(full_path));
            }
        } else if (exists) {
            config->creating = (event->mask & IN_CREATE) != 0;
            add_watches_walk(loop->inotify_fd, dir_fd, event->name, full_path, dir_root,
                             config->flags, config, 2);
            config->creating = 0;
        }
        if (dir_fd != -1) {
            close(dir_fd);
        }
    }

    // Directory watches always carry DIR_WATCH_EVENTS to follow the tree;
    // only run the command for the events that were asked for. These are
    // debounced on their own so they cannot swallow a write to a new file
    // that follows
    if (asked && exists && loop->now - loop->last_create >= config->debounce_t) {
        stop_command();
        printf(CYAN "+ Trigger on %s: [ %s ]\n" RESET, shown_name(full_path), describe(asked));
        start_command(config->command);
        loop->last_create = loop->now;
    }
}

// Events were lost: walk every root again. New files and directories are
// watched and cached, names that were not found again are dropped, and every
// file whose content differs from its cache entry is marked changed. Without
// a cache what changed is not known: the command is run
static void rescan(event_loop *loop) {
    sqwatch_config *config = loop->config;
    config->scan++;
    for (int r = 0; r < config->root_count; r++) {
        watch_root *root = &config->roots[r];
        if (root->rel) {
            reopen_file_root(root);
        }
        add_watches_walk(loop->inotify_fd, root->fd, root->rel ? root->rel : ".", root->shown, r,
                         config->flags, config, 1);
    }

    char **stale = NULL;
    size_t count = 0, size = 0;
    for (size_t s = 0; s < config->watches.size; s++) {
        const watch_entry *entry = &config->watches.slots[s];
        for (int n = 0; entry->wd >= 0 && n < entry->name_count; n++) {
            if (entry->names[n].seen == config->scan) {
                continue;
            }
            if (count == size) {
                size_t new_size = size ? size * 2 : 64;
                char **grown = realloc(stale, new_size * sizeof(*grown));
                if (!grown) {
                    break;
                }
                stale = grown;
                size = new_size;
            }
            stale[count] = strdup(entry->names[n].path);
            if (stale[count]) {
                count++;
            }
        }
    }
    for (size_t i = 0; i < count; i++) {
        drop_name(loop->inotify_fd, config, stale[i]);
        free(stale[i]);
    }
    free(stale);

    if (!config->diff_enabled || !cache_dir) {
        stop_command();
        start_command(config->command);
        return;
    }
    size_t files;
    int *wds = file_watch_list(&config->watches, &files);
    for (size_t i = 0; i < files; i++) {
        watch_entry *entry = watch_find(&config->watches, wds[i]);
        if (!entry->cached || entry->changed) {
            continue;
        }
        int n;
        int fd = open_entry(config, entry, &n);
        char io_path[FD_PATH_LEN];
        if (fd != -1 && cache_differs(fd_path(fd, io_path, sizeof(io_path)), entry->cached)) {
            mark_changed(config, wds[i], CHANGED_RESCAN);
        }
        if (fd != -1) {
            close(fd);
        }
    }
    free(wds);
}

// Diff the files marked changed, under the first name that leads to them. One that took over
// the cache entry of a name it replaced is diffed without a trigger line, as
// a rearmed watch always was; one a rescan found changed is reported
static void diff_changed(event_loop *loop) {
    sqwatch_config *config = loop->config;
    for (size_t i = 0; i < config->changed_count; i++) {
        watch_entry *entry = watch_find(&config->watches, config->changed[i]);
        if (!entry) {
            continue;
        }
        int why = entry->changed;
        entry->changed = 0;
        int n;
        int fd = open_entry(config, entry, &n);
        if (fd == -1) {
            continue;
        }
        char *path = strdup(entry->names[n].path);
        char io_path[FD_PATH_LEN];
        struct stat st;
        // A file just created may not be written yet: the write, which its
        // watch now sees, is diffed then
        int unwritten = why == CHANGED_CREATED && fstat(fd, &st) == 0 && st.st_size == 0;
        if (path && !unwritten) {
            fire_file(loop, config->changed[i], path, fd_path(fd, io_path, sizeof(io_path)),
                      why == CHANGED_RESCAN ? IN_MODIFY : IN_IGNORED, why != CHANGED_RESCAN, 1);
        }
        free(path);
        close(fd);
    }
    config->changed_count = 0;
}

// Handle inotify events until SIGINT or SIGTERM is read from signal_fd, and
// return that signal
int handle_events(int inotify_fd, int signal_fd, sqwatch_config *config) {
    char buffer[BUF_LEN];
    event_loop loop = {inotify_fd, config, 0, 0, 0};

    while (1) {
        struct pollfd fds[2] = {{inotify_fd, POLLIN, 0}, {signal_fd, POLLIN, 0}};
        if (poll(fds, 2, -1) == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            exit(EXIT_FAILURE);
        }
        if (fds[1].revents & POLLIN) {
            struct signalfd_siginfo info;
            if (read(signal_fd, &info, sizeof(info)) == (ssize_t)sizeof(info)) {
                return (int)info.ssi_signo;
            }
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
            exit(EXIT_FAILURE);
        }

        loop.now = time(NULL);
        size_t i = 0;
        while (i + EVENT_SIZE <= (size_t)length) {
            // A buffer of events can take long to handle: leave between them
            // if a signal is waiting
            stop_if_signalled();
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            i += EVENT_SIZE + event->len;
            struct inotify_event *next = i + EVENT_SIZE <= (size_t)length ?
                (struct inotify_event *)&buffer[i] : NULL;

            if (event->wd < 0) {
                if (event->mask & IN_Q_OVERFLOW) {
                    fprintf(stderr, RED "+ inotify event queue overflowed; events lost, rescanning\n" RESET);
                    rescan(&loop);
                }
            } else {
                watch_entry *watched = watch_find(&config->watches, event->wd);
                if (watched && watched->is_dir) {
                    on_dir_event(&loop, event->wd, event, next);
                } else if (watched) {
                    on_file_event(&loop, event->wd, event->mask);
                }
            }
            diff_changed(&loop);
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
