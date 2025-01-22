#ifndef DIFF_H
#define DIFF_H

#include <stddef.h>

// Colors for output formatting
#define RED "\033[31m"
#define GREEN "\033[32m"
#define RESET "\033[0m"
#define DARK_GREY "\033[90m"
#define CYAN "\033[36m"

typedef struct {
    char **lines;
    int count;
} file_lines;

// Function declarations
void run_diff(const char *path, const char *cache_dir, const char *event_type, int verbose, const char *log_file);
void print_diff(file_lines *current, file_lines *cached, int verbose);
void read_file(const char *filename, char **content, size_t *length);
void log_changes(const char *log_file, const char *path, const char *event_type, 
                file_lines *current, file_lines *cached);

#endif // DIFF_H 