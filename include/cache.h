#ifndef CACHE_H
#define CACHE_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

// Colors for output formatting
#define DARK_GREY "\033[90m"
#define RED "\033[31m"
#define RESET "\033[0m"

extern int cache_dir_owned;
extern int cache_dir_fd;

// Function declarations
int open_cache_file(const char *path, int flags);
int copy_file(const char *src, const char *dest);
int unlink_cache_file(const char *path);
void remove_directory(const char *path);
int create_caches(const char *cache_dir);
void create_cache_for_file(const char *path, const char *io_path, const char *cache_dir,
                          char **cached_path, int verbose);
#endif // CACHE_H
