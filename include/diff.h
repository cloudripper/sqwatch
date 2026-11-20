#ifndef DIFF_H
#define DIFF_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Colors for output formatting
#define RED "\033[31m"
#define GREEN "\033[32m"
#define RESET "\033[0m"
#define DARK_GREY "\033[90m"
#define CYAN "\033[36m"

#define MAX_BIN_DIFFS 16

// A text file larger than this, or with more lines, is not diffed line by
// line: it is only said to have changed
#define DIFF_MAX_BYTES (8 << 20)
#define DIFF_MAX_LINES 1000000
// Lines removed plus lines added past which the changes are not worked out
// line by line: the whole file is said to have changed. The work spent
// looking for them is bounded too
#define DIFF_MAX_EDITS 2000
#define DIFF_MAX_STEPS 200000000L
// At most this many lines, and bytes, of one diff are shown, and logged; the
// rest are counted in a note
#define DIFF_SHOW_LINES 500
#define DIFF_SHOW_BYTES (1 << 20)

// A file read whole into one buffer, each line ended by a NUL in place of its
// newline. Line i starts at data + start[i]; start[count] is one past the
// NUL of the last line. data is NULL for an empty file
typedef struct {
    char *data;
    uint32_t *start;
    int count;
} file_lines;

// Lines removed from the cached copy and lines added in the current file at
// one place, with no line in common between them
typedef struct {
    int cached_at;           // Index of the first line removed, or where
    int removed;             // lines are added if none is
    int current_at;          // Index of the first line added, or of the line
    int added;               // where lines were removed if none is
} diff_hunk;

struct diff_entry {
    size_t offset;
    unsigned char local;
    unsigned char cache;
};

// Function declarations
// path is the name shown in messages and the log; io_path is what is read
void run_diff(const char *path, const char *io_path, const char *cached_file_path, const char *event_type, int verbose, const char *log_file);
void print_diff(const file_lines *current, const file_lines *cached, const diff_hunk *hunks,
                int count, int verbose);
void log_changes(const char *log_file, const char *path, const char *event_type,
                 const file_lines *current, const file_lines *cached, const diff_hunk *hunks,
                 int count);
int is_binary_file(const char *filename, const char *io_path);
void print_bin_diff(const char *path, const char *io_path, const char *cached_file_path, const char *log_file);
void log_bin_diff(const char *log_file, const char *path, 
                 const struct diff_entry *diffs, size_t diff_count);
#endif // DIFF_H 