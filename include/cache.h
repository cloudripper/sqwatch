#ifndef CACHE_H
#define CACHE_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>

// Colors for output formatting
#define DARK_GREY "\033[90m"
#define RED "\033[31m"
#define RESET "\033[0m"

// A watched file larger than this is not copied into the cache, nor one that
// would take all the copies together over the budget; see copy_file()
#define CACHE_MAX_BYTES (64 << 20)
#define CACHE_BUDGET_BYTES (256 << 20)
// What a cache entry that holds no copy keeps instead: see cache_stub()
#define STUB_TOO_LARGE 1
#define STUB_BUDGET 2

extern int cache_dir_owned;
extern int cache_dir_fd;

// Function declarations
int open_cache_file(const char *path, int flags);
int open_watched_file(const char *io_path);
int copy_file(const char *src, const char *dest, const char *shown_path);
char *cache_new_entry(const char *cache_dir);
char *cache_copy_entry(const char *cache_dir, const char *src);
int unlink_cache_file(const char *path);
int cache_differs(const char *io_path, const char *path);
int cache_unchanged(const char *io_path, const char *path);
int cache_stub(const char *path, off_t *size, struct timespec *mtime);
void remove_caches(void);
int create_caches(const char *cache_dir);
int open_log_file(const char *log_file);
int is_log_file(int fd);
int is_log_name(int dir_fd, const char *name);
int is_cache_dir(int fd);
FILE *log_begin(void);
void log_end(void);
void create_cache_for_file(const char *path, const char *io_path, const char *cache_dir,
                          char **cached_path, int verbose);
#endif // CACHE_H
