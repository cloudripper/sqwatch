#ifndef CACHE_H
#define CACHE_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

// Colors for output formatting
#define DARK_GREY "\033[90m"
#define RED "\033[31m"
#define RESET "\033[0m"

// Function declarations
int copy_file(const char *src, const char *dest);
void remove_directory(const char *path);
void create_caches(int max_files, const char *cache_dir, char *watch_paths[], char *cached_paths[]);

#endif // CACHE_H 