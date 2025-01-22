#include "diff.h"
#include "cache.h"
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define MAX_LINE_LENGTH 1024

static void free_file_lines(file_lines *fl) {
    if (fl->lines) {
        for (int i = 0; i < fl->count; i++) {
            free(fl->lines[i]);
        }
        free(fl->lines);
    }
}

static file_lines read_file_lines(const char *filename) {
    file_lines fl = {NULL, 0};
    int retry_count = 0;
    FILE *file = NULL;
    
    // Try to open the file a few times with a small delay
    while ((file = fopen(filename, "r")) == NULL && retry_count < 3) {
        usleep(10000);  // Wait 10ms between retries
        retry_count++;
    }

    if (!file) {
        fprintf(stderr, RED "Failed to open %s after %d retries: %s\n" RESET, 
                filename, retry_count, strerror(errno));
        return fl;
    }

    // Get file size with retries for empty files
    struct stat st;
    retry_count = 0;
    int fd = fileno(file);
    
    while (retry_count < 5) {  // Try up to 5 times
        if (fstat(fd, &st) < 0) {
            fprintf(stderr, RED "Failed to stat %s: %s\n" RESET, filename, strerror(errno));
            fclose(file);
            return fl;
        }

        if (st.st_size > 0) {
            break;  // File has content, proceed
        }

        // Wait before retry
        usleep(50000);  // 50ms delay between attempts
        retry_count++;
    }

    if (st.st_size == 0) {
        fprintf(stderr, RED "File %s is empty after %d attempts\n" RESET, filename, retry_count);
        fclose(file);
        return fl;
    }

    // Initialize buffer with reasonable capacity
    char line[MAX_LINE_LENGTH];
    int capacity = 16;
    fl.lines = malloc(capacity * sizeof(char *));
    if (!fl.lines) {
        fprintf(stderr, RED "Failed to allocate initial buffer\n" RESET);
        fclose(file);
        return fl;
    }

    // Read lines using fgets
    while (fgets(line, sizeof(line), file)) {
        // Remove trailing newline if present
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }

        if (fl.count == capacity) {
            capacity *= 2;
            char **new_lines = realloc(fl.lines, capacity * sizeof(char *));
            if (!new_lines) {
                fprintf(stderr, RED "Memory allocation failed\n" RESET);
                free_file_lines(&fl);
                fclose(file);
                return (file_lines){NULL, 0};
            }
            fl.lines = new_lines;
        }

        fl.lines[fl.count] = strdup(line);
        if (!fl.lines[fl.count]) {
            fprintf(stderr, RED "Failed to strdup line\n" RESET);
            free_file_lines(&fl);
            fclose(file);
            return (file_lines){NULL, 0};
        }
        fl.count++;
    }

    fclose(file);
    return fl;
}

void print_diff(file_lines *current, file_lines *cached, int verbose) {
    if (!verbose) return;
    // test

    

    int i = 0, j = 0;
    int context_lines = 3;  // Number of unchanged lines to show around changes
    int in_change_block = 0;
    int lines_since_change = 0;

    while (i < current->count && j < cached->count) {
        if (strcmp(current->lines[i], cached->lines[j]) == 0) {
            // Lines match - show context if needed
            if (in_change_block && lines_since_change < context_lines) {
                printf("  %d: %s\n", i + 1, current->lines[i]);
            }
            lines_since_change++;
            if (lines_since_change >= context_lines) {
                in_change_block = 0;
            }
            i++;
            j++;
        } else {
            // Lines differ - find next matching line
            int next_match_i = i;
            int next_match_j = j;
            int found_match = 0;

            // Look ahead for next matching line
            for (int look_ahead = 1; look_ahead <= 10; look_ahead++) {
                if (i + look_ahead < current->count && 
                    j < cached->count && 
                    strcmp(current->lines[i + look_ahead], cached->lines[j]) == 0) {
                    // Found match in current file
                    next_match_i = i + look_ahead;
                    next_match_j = j;
                    found_match = 1;
                    break;
                }
                if (i < current->count && 
                    j + look_ahead < cached->count && 
                    strcmp(current->lines[i], cached->lines[j + look_ahead]) == 0) {
                    // Found match in cached file
                    next_match_i = i;
                    next_match_j = j + look_ahead;
                    found_match = 1;
                    break;
                }
            }

            // Print the changes
            if (!in_change_block) {
                printf("\n");  // Separate change blocks
            }
            in_change_block = 1;
            lines_since_change = 0;

            // Print removed lines
            while (j < next_match_j) {
                printf(RED "-%d: %s\n" RESET, j + 1, cached->lines[j]);
                j++;
            }
            // Print added lines
            while (i < next_match_i) {
                printf(GREEN "+%d: %s\n" RESET, i + 1, current->lines[i]);
                i++;
            }

            if (!found_match) {
                // No match found within look-ahead window
                i++;
                j++;
            }
        }
    }

    // Print any remaining lines
    while (i < current->count) {
        printf(GREEN "+%d: %s\n" RESET, i + 1, current->lines[i]);
        i++;
    }
    while (j < cached->count) {
        printf(RED "-%d: %s\n" RESET, j + 1, cached->lines[j]);
        j++;
    }
}

// Helper function to get current timestamp
static char* get_timestamp() {
    time_t now = time(NULL);
    char* timestamp = ctime(&now);
    // Remove newline from ctime output
    timestamp[strlen(timestamp) - 1] = '\0';
    return timestamp;
}

// Modified log_changes to include the diff output
void log_changes(const char *log_file, const char *path, const char *event_type, 
                file_lines *current, file_lines *cached) {
    if (!log_file) return;

    FILE *log_fp = fopen(log_file, "a");
    if (!log_fp) {
        perror(RED "Failed to open log file" RESET);
        return;
    }

    // Write header with filename, event type, and timestamp
    fprintf(log_fp, "\n%s %s %s:\n", path, event_type, get_timestamp());

    // Write diff in patch format
    // test
    int i = 0, j = 0;
    while (i < current->count && j < cached->count) {
        if (strcmp(current->lines[i], cached->lines[j]) == 0) {
            i++;
            j++;
        } else {
            int next_match_i = i;
            int next_match_j = j;
            int found_match = 0;

            // Look ahead for next matching line
            for (int look_ahead = 1; look_ahead <= 10; look_ahead++) {
                if (i + look_ahead < current->count && 
                    j < cached->count && 
                    strcmp(current->lines[i + look_ahead], cached->lines[j]) == 0) {
                    next_match_i = i + look_ahead;
                    next_match_j = j;
                    found_match = 1;
                    break;
                }
                if (i < current->count && 
                    j + look_ahead < cached->count && 
                    strcmp(current->lines[i], cached->lines[j + look_ahead]) == 0) {
                    next_match_i = i;
                    next_match_j = j + look_ahead;
                    found_match = 1;
                    break;
                }
            }

            // Write removed lines with line numbers
            while (j < next_match_j) {
                fprintf(log_fp, "-%d: %s\n", j + 1, cached->lines[j]);
                j++;
            }
            // Write added lines with line numbers
            while (i < next_match_i) {
                fprintf(log_fp, "+%d: %s\n", i + 1, current->lines[i]);
                i++;
            }

            if (!found_match) {
                i++;
                j++;
            }
        }
    }

    // Write remaining lines with line numbers
    while (i < current->count) {
        fprintf(log_fp, "+%d: %s\n", i + 1, current->lines[i]);
        i++;
    }
    while (j < cached->count) {
        fprintf(log_fp, "-%d: %s\n", j + 1, cached->lines[j]);
        j++;
    }

    fprintf(log_fp, "\n"); // Add blank line after diff
    fclose(log_fp);
}

void run_diff(const char *path, const char *cache_dir, const char *event_type, int verbose, const char *log_file) {
    char *path_copy = strdup(path);
    
    if (!path_copy) {
        perror(RED "Failed to allocate memory for path_copy" RESET);
        return;
    }

    char *cached_file_path = malloc(strlen(cache_dir) + strlen(basename(path_copy)) + 2);
    if (!cached_file_path) {
        perror(RED "Failed to allocate memory for cached_file_path" RESET);
        free(path_copy);
        return;
    }

    sprintf(cached_file_path, "%s/%s", cache_dir, basename(path_copy));

    // Read both files into lines
    file_lines current = read_file_lines(path);
    file_lines cached = read_file_lines(cached_file_path);

    if (current.lines && cached.lines) {
        // Print the changes
        print_diff(&current, &cached, verbose);
        
        // Count changes for logging
        int changes = abs(current.count - cached.count);
        for (int i = 0; i < current.count && i < cached.count; i++) {
            if (strcmp(current.lines[i], cached.lines[i]) != 0) {
                changes++;
            }
        }

        if (changes > 0) {
            char change_msg[256];
            snprintf(change_msg, sizeof(change_msg), 
                    "%s: %d change%s in %s", 
                    event_type, changes, changes == 1 ? "" : "s", path);
            printf(CYAN "+ %s\n" RESET, change_msg);
            fflush(stdout);
            
            if (log_file) {
                log_changes(log_file, path, event_type, &current, &cached);
            }

            // Update the cache file with the current content
            if (copy_file(path, cached_file_path) != 0) {
                fprintf(stderr, RED "Failed to update cache file: %s\n" RESET, cached_file_path);
            }
        }
    }

    // Cleanup
    free_file_lines(&current);
    free_file_lines(&cached);
    free(cached_file_path);
    free(path_copy);
} 
