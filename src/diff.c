#include "cache.h"
#include "diff.h"
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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
    usleep(10000); // Wait 10ms between retries
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
  while (retry_count < 5) { // Try up to 5 times
    if (fstat(fd, &st) < 0) {
      fprintf(stderr, RED "Failed to stat %s: %s\n" RESET, filename,
              strerror(errno));
      fclose(file);
      return fl;
    }

    if (st.st_size > 0) {
      break; // File has content, proceed
    }

    // Wait before retry
    usleep(50000); // 50ms delay between attempts
    retry_count++;
  }

  if (st.st_size == 0) {
    fprintf(stderr, DARK_GREY "File %s is empty after %d attempts\n" RESET, filename,
            retry_count);
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
    if (len > 0 && line[len - 1] == '\n') {
      line[len - 1] = '\0';
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
  if (!verbose)
    return;

  int i = 0, j = 0;
  int context_lines = 0;
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
      // Check for single line modification first
      int next_i = i + 1;
      int next_j = j + 1;
      if (next_i < current->count && next_j < cached->count &&
          strcmp(current->lines[next_i], cached->lines[next_j]) == 0) {
        // Single line modification detected
        if (!in_change_block) {
          printf("\n");
        }
        in_change_block = 1;
        lines_since_change = 0;
        printf(RED "-%d: %s\n" RESET, j + 1, cached->lines[j]);
        printf(GREEN "+%d: %s\n" RESET, i + 1, current->lines[i]);
        i++;
        j++;
        continue;
      }

      // Lines differ - find next matching line
      int next_match_i = i;
      int next_match_j = j;
      int found_match = 0;

      // Look ahead for next matching line
      for (int look_ahead = 1; look_ahead <= 10; look_ahead++) {
        if (i + look_ahead < current->count && j < cached->count &&
            strcmp(current->lines[i + look_ahead], cached->lines[j]) == 0) {
          // Found match in current file
          next_match_i = i + look_ahead;
          next_match_j = j;
          found_match = 1;
          break;
        }
        if (i < current->count && j + look_ahead < cached->count &&
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
        printf("\n");
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
  printf(RESET "\n");
}

// Modified log_changes to include the diff output
void log_changes(const char *log_file, const char *path, const char *event_type,
                 file_lines *current, file_lines *cached) {
  if (!log_file)
    return;

  FILE *log_fp = fopen(log_file, "a");
  if (!log_fp) {
    perror(RED "Failed to open log file" RESET);
    return;
  }

  time_t now = time(NULL);
  char *timestamp = ctime(&now);
  timestamp[strlen(timestamp) - 1] = '\0';

  fprintf(log_fp, "\n=== Text File Diff ===\n");
  fprintf(log_fp, "Time: %s\n", timestamp);
  fprintf(log_fp, "File: %s\n", path);
  fprintf(log_fp, "Event: %s\n", event_type);

  int i = 0, j = 0;
  int in_change_block = 0;

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
        if (i + look_ahead < current->count && j < cached->count &&
            strcmp(current->lines[i + look_ahead], cached->lines[j]) == 0) {
          next_match_i = i + look_ahead;
          next_match_j = j;
          found_match = 1;
          break;
        }
        if (i < current->count && j + look_ahead < cached->count &&
            strcmp(current->lines[i], cached->lines[j + look_ahead]) == 0) {
          next_match_i = i;
          next_match_j = j + look_ahead;
          found_match = 1;
          break;
        }
      }

      // Print change block separator
      if (!in_change_block) {
        fprintf(log_fp, "\n");
      }
      in_change_block = 1;

      while (j < next_match_j) {
        fprintf(log_fp, "-%d: %s\n", j + 1, cached->lines[j]);
        j++;
      }
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

  // Handle remaining lines exactly like print_diff
  if (i < current->count || j < cached->count) {
    fprintf(log_fp, "\n"); // Separator for final block
  }

  while (i < current->count) {
    fprintf(log_fp, "+%d: %s\n", i + 1, current->lines[i]);
    i++;
  }
  while (j < cached->count) {
    fprintf(log_fp, "-%d: %s\n", j + 1, cached->lines[j]);
    j++;
  }

  fprintf(log_fp, "=== End Text Diff ===\n\n");
  fclose(log_fp);
}

int is_binary_file(const char *filename) {
  unsigned char buffer[4096];
  size_t bytes_read = 0;
  int retry_count = 0;
  const int max_retries = 3;

  while (retry_count < max_retries) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
      fprintf(stderr, RED "Cannot open %s: %s\n" RESET, filename,
              strerror(errno));
      return -1;
    }

    bytes_read = fread(buffer, 1, sizeof(buffer), file);

    fclose(file);

    if (bytes_read > 0) {
      for (size_t i = 0; i < bytes_read; i++) {
        if (buffer[i] == 0x00) {
          return 1; // Found null byte, likely binary
        }
      }
      return 0; // No null bytes found, treat as text
    }

    usleep(1000 * (retry_count + 1));
    retry_count++;
  }

  fprintf(stderr, RED "Failed to read %s after %d attempts\n" RESET, filename,
          max_retries);
  return -1; // Failed to read file after retries
}

void run_diff(const char *path, const char *cache_dir, const char *event_type,
              int verbose, const char *log_file) {
  char *path_copy = strdup(path);

  if (!path_copy) {
    perror(RED "Failed to allocate memory for path_copy" RESET);
    return;
  }

  char *cached_file_path =
      malloc(strlen(cache_dir) + strlen(basename(path_copy)) + 2);
  if (!cached_file_path) {
    perror(RED "Failed to allocate memory for cached_file_path" RESET);
    free(path_copy);
    return;
  }
  sprintf(cached_file_path, "%s/%s", cache_dir, basename(path_copy));

  // Check if file is binary
  int bin_check = is_binary_file(path);
  if (bin_check > 0) {
    if (verbose) {
      printf(DARK_GREY "Binary file detected: %s\n" RESET, path);
      print_bin_diff(path, cached_file_path, log_file);
    }

    // Still update the cache for binary files
    if (copy_file(path, cached_file_path) != 0) {
      fprintf(stderr, RED "Failed to update cache file: %s\n" RESET,
              cached_file_path);
    }

    free(path_copy);
    free(cached_file_path);
    return;
  } else if (bin_check < 0) {
    fprintf(stderr, RED "Failed to read %s.\n" RESET, path);
    free(path_copy);
    free(cached_file_path);
    return;
  }

  file_lines current = read_file_lines(path);
  file_lines cached = read_file_lines(cached_file_path);

  // First check if either file is empty
  if (!current.lines || !cached.lines) {
    if (!current.lines && cached.lines) {
      // File was emptied
      printf(RED "- File emptied\n" RESET);
      if (log_file) {
        log_changes(log_file, path, "Emptied", &current, &cached);
      }
    } else if (current.lines && !cached.lines) {
      // New content added to empty file
      printf(GREEN "+ New content added\n" RESET);
      if (log_file) {
        log_changes(log_file, path, "New content", &current, &cached);
      }
    }
    
    // Update cache regardless of which case
    if (copy_file(path, cached_file_path) != 0) {
      fprintf(stderr, RED "Failed to update cache file: %s\n" RESET,
              cached_file_path);
    }
    return;
  }

  // Both files have content, proceed with normal diff
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
      if (log_file) {
        log_changes(log_file, path, event_type, &current, &cached);
      }

      // Update the cache file with the current content
      if (copy_file(path, cached_file_path) != 0) {
        fprintf(stderr, RED "Failed to update cache file: %s\n" RESET,
                cached_file_path);
      }
    }
  }

  // Cleanup
  free_file_lines(&current);
  free_file_lines(&cached);
  free(cached_file_path);
  free(path_copy);
}

void print_bin_diff(const char *path, const char *cached_path,
                    const char *log_file) {
  FILE *f1 = fopen(path, "rb");
  FILE *f2 = fopen(cached_path, "rb");

  if (!f1 || !f2) {
    if (f1)
      fclose(f1);
    if (f2)
      fclose(f2);
    return;
  }

  unsigned char buf1[MAX_BIN_DIFFS], buf2[MAX_BIN_DIFFS];
  struct diff_entry diffs[MAX_BIN_DIFFS]; // Store up to 10 differences

  size_t offset = 0;
  int differences = 0;
  int continue_reading = 1;

  while (continue_reading) {
    size_t n1 = fread(buf1, 1, sizeof(buf1), f1);
    size_t n2 = fread(buf2, 1, sizeof(buf2), f2);

    if (n1 == 0 && n2 == 0)
      break;

    if (n1 != n2) {
      printf(RED "Files have different sizes at offset %08zx (local: %zu != "
                 "cache: %zu)\n" RESET,
             offset, n1, n2);
      break;
    }

    size_t compare_len = (n1 < n2) ? n1 : n2;
    for (size_t i = 0; i < compare_len && continue_reading; i++) {
      if (buf1[i] != buf2[i]) {
        printf("%08zx: " RED "%02x" RESET " -> " GREEN "%02x" RESET "\n",
               offset + i, buf2[i], buf1[i]);

        if (differences < MAX_BIN_DIFFS) {
          diffs[differences].offset = offset + i;
          diffs[differences].local = buf1[i];
          diffs[differences].cache = buf2[i];
        }

        differences++;

        if (differences >= MAX_BIN_DIFFS) {
          printf(DARK_GREY "... more differences follow ...\n" RESET);
          continue_reading = 0;
          break;
        }
      }
    }

    offset += n1;
  }

  if (log_file && differences > 0) {
    log_bin_diff(log_file, path, diffs, differences);
  }

  fclose(f1);
  fclose(f2);
}

void log_bin_diff(const char *log_file, const char *path,
                  const struct diff_entry *diffs, size_t diff_count) {
  if (!log_file)
    return;

  FILE *log_fp = fopen(log_file, "a");
  if (!log_fp) {
    fprintf(stderr, RED "Failed to open log file for binary diff: %s\n" RESET,
            strerror(errno));
    return;
  }

  time_t now = time(NULL);
  char *timestamp = ctime(&now);
  timestamp[strlen(timestamp) - 1] = '\0';

  fprintf(log_fp, "\n=== Binary File Diff ===\n");
  fprintf(log_fp, "Time: %s\n", timestamp);
  fprintf(log_fp, "File: %s\n", path);
  fprintf(log_fp, "Offset: 0x%08zx\n",
          diffs[0].offset & ~0xF); // Base offset of first change

  size_t log_count = diff_count > MAX_BIN_DIFFS ? MAX_BIN_DIFFS : diff_count;
  for (size_t i = 0; i < log_count; i++) {
    fprintf(log_fp, "0x%08zx: %02x -> %02x\n", diffs[i].offset, diffs[i].cache,
            diffs[i].local);
  }

  if (diff_count >= MAX_BIN_DIFFS) {
    fprintf(log_fp, "More differences follow ...\n");
  }

  fprintf(log_fp, "=== End Binary Diff ===\n\n");
  fclose(log_fp);
}
