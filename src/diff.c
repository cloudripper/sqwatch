#include "cache.h"
#include "diff.h"
#include "sqwatch.h"
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void free_file_lines(file_lines *fl) {
  free(fl->data);
  free(fl->start);
  fl->data = NULL;
  fl->start = NULL;
}

// Open a cache file for reading; see open_cache_file()
static FILE *fopen_cache(const char *path) {
  int fd = open_cache_file(path, O_RDONLY);
  FILE *file = fd < 0 ? NULL : fdopen(fd, "r");
  if (fd >= 0 && !file) {
    close(fd);
  }
  return file;
}

// Open a watched file; see open_watched_file()
static FILE *fopen_watched(const char *io_path, const char *mode) {
  int fd = open_watched_file(io_path);
  FILE *file = fd < 0 ? NULL : fdopen(fd, mode);
  if (fd >= 0 && !file) {
    close(fd);
  }
  return file;
}

// Every 256 steps through the lines of a diff, leave if a signal is waiting
static void check_signals_every_256(int *steps) {
  if ((++*steps & 255) == 0) {
    stop_if_signalled();
  }
}

// Why read_file_lines() did not read a file
enum { READ_OK, READ_LEASED, READ_TOO_LARGE, READ_TOO_MANY_LINES };

// filename is the name shown in messages; the file is read through io_path,
// which names a file in the cache directory if cache_side is set. The whole
// file is read into one buffer, and split at every newline however long its
// lines are. *why says if the file was skipped: another process holds a lease
// on it, or it is over DIFF_MAX_BYTES or DIFF_MAX_LINES; *size is then its size
static file_lines read_file_lines(const char *filename, const char *io_path, int cache_side,
                                  int *why, long long *size) {
  file_lines fl = {NULL, NULL, 0};
  int retry_count = 0;
  FILE *file = NULL;
  *why = READ_OK;

  // Try to open the file a few times with a small delay
  while ((file = cache_side ? fopen_cache(io_path) : fopen_watched(io_path, "r")) == NULL &&
         errno != EWOULDBLOCK && retry_count < 3) {
    usleep(10000); // Wait 10ms between retries
    retry_count++;
  }
  if (!file && errno == EWOULDBLOCK) {
    fprintf(stderr, RED "+ Skipping %s this time: another process holds a lease on it\n" RESET,
            shown_name(filename));
    *why = READ_LEASED;
    return fl;
  }
  if (!file) {
    fprintf(stderr, RED "Failed to open %s after %d retries: %s\n" RESET,
            shown_name(filename), retry_count, strerror(errno));
    return fl;
  }

  // Get file size with retries for empty files
  struct stat st;
  retry_count = 0;
  int fd = fileno(file);
  while (retry_count < 5) { // Try up to 5 times
    if (fstat(fd, &st) < 0) {
      fprintf(stderr, RED "Failed to stat %s: %s\n" RESET, shown_name(filename),
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
    fprintf(stderr, DARK_GREY "File %s is empty after %d attempts\n" RESET, shown_name(filename),
            retry_count);
    fclose(file);
    return fl;
  }
  *size = st.st_size;
  if (st.st_size > DIFF_MAX_BYTES) {
    *why = READ_TOO_LARGE;
    fclose(file);
    return fl;
  }

  // Read it all, one MiB at a time; it may have grown since fstat()
  size_t length = 0, room = (size_t)st.st_size + 1;
  char *data = malloc(room);
  while (data) {
    if (length + 1 == room) {
      if (room > DIFF_MAX_BYTES) {
        *why = READ_TOO_LARGE;
        *size = (long long)length;
        break;
      }
      char *grown = realloc(data, room * 2 > DIFF_MAX_BYTES + 2 ? DIFF_MAX_BYTES + 2 : room * 2);
      if (!grown) {
        free(data);
        data = NULL;
        break;
      }
      room = room * 2 > DIFF_MAX_BYTES + 2 ? DIFF_MAX_BYTES + 2 : room * 2;
      data = grown;
    }
    size_t want = room - 1 - length;
    ssize_t n = read(fd, data + length, want > (1 << 20) ? (1 << 20) : want);
    if (n <= 0) {
      break;
    }
    length += (size_t)n;
    stop_if_signalled();
  }
  fclose(file);
  if (!data) {
    fprintf(stderr, RED "Memory allocation failed\n" RESET);
    return fl;
  }
  if (*why != READ_OK || length == 0) {
    free(data);
    return fl;
  }
  data[length] = '\0';

  // One line per newline, and one more for text after the last newline
  size_t lines = 0;
  for (char *p = data; (p = memchr(p, '\n', length - (size_t)(p - data))) != NULL; p++) {
    lines++;
  }
  if (data[length - 1] != '\n') {
    lines++;
  }
  if (lines > DIFF_MAX_LINES) {
    *why = READ_TOO_MANY_LINES;
    *size = (long long)lines;
    free(data);
    return fl;
  }
  fl.start = malloc((lines + 1) * sizeof(*fl.start));
  if (!fl.start) {
    fprintf(stderr, RED "Memory allocation failed\n" RESET);
    free(data);
    return fl;
  }
  size_t at = 0;
  for (size_t line = 0; line < lines; line++) {
    fl.start[line] = (uint32_t)at;
    char *end = memchr(data + at, '\n', length - at);
    if (end) {
      *end = '\0';
      at = (size_t)(end - data) + 1;
    } else {
      at = length + 1;  // The NUL after the buffer ends it
    }
  }
  fl.start[lines] = (uint32_t)at;
  fl.data = data;
  fl.count = (int)lines;
  return fl;
}

static const char *line_at(const file_lines *fl, int i) {
  return fl->data + fl->start[i];
}

static int same_line(const file_lines *a, int i, const file_lines *b, int j) {
  uint32_t len = a->start[i + 1] - a->start[i];
  return len == b->start[j + 1] - b->start[j] && memcmp(line_at(a, i), line_at(b, j), len) == 0;
}

// Find the lines removed from cached and added in current with the fewest of
// them (Myers' algorithm), after the lines both start and end with are set
// aside, so that a common edit costs little however long the files are. Sets *hunks (to free) and *count. Returns -1, and no hunks, if more
// than DIFF_MAX_EDITS lines changed or the search takes more than
// DIFF_MAX_STEPS comparisons; the files differ then
static int diff_lines(const file_lines *current, const file_lines *cached, diff_hunk **hunks,
                      int *count) {
  int n = cached->count, m = current->count;
  int head = 0, tail = 0;
  *hunks = NULL;
  *count = 0;
  while (head < n && head < m && same_line(cached, head, current, head)) {
    head++;
  }
  while (tail < n - head && tail < m - head &&
         same_line(cached, n - 1 - tail, current, m - 1 - tail)) {
    tail++;
  }
  int a_len = n - head - tail, b_len = m - head - tail;
  if (a_len == 0 && b_len == 0) {
    return 0;
  }
  if (a_len == 0 || b_len == 0) {
    // Only lines added, or only lines removed, at one place
    *hunks = malloc(sizeof(**hunks));
    if (!*hunks) {
      return -1;
    }
    **hunks = (diff_hunk){head, a_len, head, b_len};
    *count = 1;
    return 0;
  }

  // v[k] is how far along cached the furthest path on diagonal k gets; the
  // values after each round d are kept in trace, 2d + 1 of them, to walk back
  int max_d = a_len + b_len < DIFF_MAX_EDITS ? a_len + b_len : DIFF_MAX_EDITS;
  int offset = max_d + 1;
  int *v = calloc(2 * (size_t)max_d + 3, sizeof(*v));
  int *trace = NULL;
  size_t trace_size = 0;
  long steps = 0;
  int found = -1;
  for (int d = 0; v && d <= max_d && found < 0 && steps <= DIFF_MAX_STEPS; d++) {
    if ((d & 63) == 0) {
      stop_if_signalled();
    }
    size_t need = ((size_t)d + 1) * ((size_t)d + 1);
    if (need > trace_size) {
      size_t new_size = trace_size ? trace_size * 2 : 1024;
      while (new_size < need) {
        new_size *= 2;
      }
      int *grown = realloc(trace, new_size * sizeof(*grown));
      if (!grown) {
        break;
      }
      trace = grown;
      trace_size = new_size;
    }
    for (int k = -d; k <= d; k += 2) {
      int x;
      if (k == -d || (k != d && v[offset + k - 1] < v[offset + k + 1])) {
        x = v[offset + k + 1];          // A line added
      } else {
        x = v[offset + k - 1] + 1;      // A line removed
      }
      int y = x - k;
      while (x < a_len && y < b_len && same_line(cached, head + x, current, head + y)) {
        x++;
        y++;
        steps++;
      }
      steps++;
      v[offset + k] = x;
      trace[(size_t)d * d + (size_t)(k + d)] = x;
      if (x >= a_len && y >= b_len) {
        found = d;
        break;
      }
    }
  }
  free(v);
  if (found < 0) {
    free(trace);
    return -1;
  }

  // Walk back from the end; each round added or removed one line
  int *ops = malloc(((size_t)found + 1) * 2 * sizeof(*ops));  // x, y of each step, last first
  int *kinds = malloc(((size_t)found + 1) * sizeof(*kinds));  // 1 added, 0 removed
  diff_hunk *out = malloc(((size_t)found + 1) * sizeof(*out));
  if (!ops || !kinds || !out) {
    free(ops);
    free(kinds);
    free(out);
    free(trace);
    return -1;
  }
  int x = a_len, y = b_len;
  for (int d = found; d > 0; d--) {
    const int *prev = &trace[(size_t)(d - 1) * (d - 1)];  // prev[k + d - 1]
    int k = x - y;
    int added = k == -d || (k != d && prev[k - 1 + d - 1] < prev[k + 1 + d - 1]);
    int prev_k = added ? k + 1 : k - 1;
    int prev_x = prev[prev_k + d - 1];
    int prev_y = prev_x - prev_k;
    // The step itself starts at (prev_x, prev_y), then a run of common lines
    // leads to (x, y)
    ops[2 * (d - 1)] = prev_x;
    ops[2 * (d - 1) + 1] = prev_y;
    kinds[d - 1] = added;
    x = prev_x;
    y = prev_y;
  }
  free(trace);

  // Steps that follow each other without a common line between make a hunk
  int hunk_count = 0;
  for (int e = 0; e < found; e++) {
    int sx = ops[2 * e], sy = ops[2 * e + 1];
    diff_hunk *last = hunk_count ? &out[hunk_count - 1] : NULL;
    if (!last || last->cached_at + last->removed != head + sx ||
        last->current_at + last->added != head + sy) {
      out[hunk_count++] = (diff_hunk){head + sx, 0, head + sy, 0};
      last = &out[hunk_count - 1];
    }
    if (kinds[e]) {
      last->added++;
    } else {
      last->removed++;
    }
  }
  free(ops);
  free(kinds);
  *hunks = out;
  *count = hunk_count;
  return 0;
}

// A hunk at the end of either file. It is shown without the blank line that
// comes before the others, as the earlier diff did
static int hunk_at_end(const diff_hunk *hunk, const file_lines *current,
                       const file_lines *cached) {
  return hunk->cached_at == cached->count || hunk->current_at == current->count;
}

// What one shown or logged diff has used of DIFF_SHOW_LINES and
// DIFF_SHOW_BYTES; the lines past either are counted, not written
typedef struct {
  int lines;
  size_t bytes;
  long long hidden;
} show_cap;

// Whether text may be written as one more line of the diff; if not, it is
// counted as hidden
static int cap_take(show_cap *cap, const char *text) {
  size_t len = strlen(text) + 16;
  if (cap->hidden || cap->lines >= DIFF_SHOW_LINES || cap->bytes + len > DIFF_SHOW_BYTES) {
    cap->hidden++;
    return 0;
  }
  cap->lines++;
  cap->bytes += len;
  return 1;
}

static void cap_note(FILE *fp, const show_cap *cap) {
  if (cap->hidden) {
    fprintf(fp, "... %lld more line%s not shown\n", cap->hidden, cap->hidden == 1 ? "" : "s");
  }
}

void print_diff(const file_lines *current, const file_lines *cached, const diff_hunk *hunks,
                int count, int verbose) {
  if (!verbose)
    return;

  int steps = 0;
  show_cap cap = {0, 0, 0};
  for (int h = 0; h < count; h++) {
    if (!cap.hidden && !hunk_at_end(&hunks[h], current, cached)) {
      printf("\n");
    }
    for (int j = hunks[h].cached_at; j < hunks[h].cached_at + hunks[h].removed; j++) {
      check_signals_every_256(&steps);
      const char *text = shown_text(line_at(cached, j));
      if (cap_take(&cap, text)) {
        printf(RED "-%d: %s\n" RESET, j + 1, text);
      }
    }
    for (int i = hunks[h].current_at; i < hunks[h].current_at + hunks[h].added; i++) {
      check_signals_every_256(&steps);
      const char *text = shown_text(line_at(current, i));
      if (cap_take(&cap, text)) {
        printf(GREEN "+%d: %s\n" RESET, i + 1, text);
      }
    }
  }
  if (cap.hidden) {
    printf(DARK_GREY);
    cap_note(stdout, &cap);
  }
  printf(RESET "\n");
}

// Start a log entry; NULL if there is no log
static FILE *log_header(const char *log_file, const char *kind, const char *path,
                        const char *event_type) {
  FILE *log_fp = log_file ? log_begin() : NULL;
  if (!log_fp)
    return NULL;

  time_t now = time(NULL);
  char *timestamp = ctime(&now);
  if (timestamp) {
    size_t tlen = strlen(timestamp);
    if (tlen > 0 && timestamp[tlen - 1] == '\n') {
        timestamp[tlen - 1] = '\0';
      }
  } else {
    timestamp = "(unknown time)";
  }

  fprintf(log_fp, "\n=== %s File Diff ===\n", kind);
  fprintf(log_fp, "Time: %s\n", timestamp);
  fprintf(log_fp, "File: %s\n", shown_name(path));
  if (event_type) {
    fprintf(log_fp, "Event: %s\n", event_type);
  }
  return log_fp;
}

// Write the diff to the log, in the layout of the earlier diff: a blank line
// before the first hunk and before one at the end of either file
void log_changes(const char *log_file, const char *path, const char *event_type,
                 const file_lines *current, const file_lines *cached, const diff_hunk *hunks,
                 int count) {
  FILE *log_fp = log_header(log_file, "Text", path, event_type);
  if (!log_fp)
    return;

  int in_change_block = 0;
  int steps = 0;
  show_cap cap = {0, 0, 0};
  for (int h = 0; h < count; h++) {
    if (!cap.hidden && (hunk_at_end(&hunks[h], current, cached) || !in_change_block)) {
      fprintf(log_fp, "\n");
    }
    in_change_block = 1;
    for (int j = hunks[h].cached_at; j < hunks[h].cached_at + hunks[h].removed; j++) {
      check_signals_every_256(&steps);
      const char *text = shown_text(line_at(cached, j));
      if (cap_take(&cap, text)) {
        fprintf(log_fp, "-%d: %s\n", j + 1, text);
      }
    }
    for (int i = hunks[h].current_at; i < hunks[h].current_at + hunks[h].added; i++) {
      check_signals_every_256(&steps);
      const char *text = shown_text(line_at(current, i));
      if (cap_take(&cap, text)) {
        fprintf(log_fp, "+%d: %s\n", i + 1, text);
      }
    }
  }
  cap_note(log_fp, &cap);

  fprintf(log_fp, "=== End Text Diff ===\n\n");
  log_end();
}

// Say that path changed without showing how: what is in parentheses says why
static void report_change(const char *path, const char *event_type, const char *log_file,
                          const char *why) {
  printf(DARK_GREY "+ %s changed, %s\n" RESET, shown_name(path), why);
  FILE *log_fp = log_header(log_file, "Text", path, event_type);
  if (log_fp) {
    fprintf(log_fp, "Changed, %s\n", why);
    fprintf(log_fp, "=== End Text Diff ===\n\n");
    log_end();
  }
}

// Whether the file has a NUL byte anywhere in its first CACHE_MAX_BYTES (a
// larger file is not diffed): 1 if so, 0 if not or if it is empty, -1 if it
// cannot be read, -2 if another process holds a lease on it
int is_binary_file(const char *filename, const char *io_path) {
  int retry_count = 0;
  const int max_retries = 3;
  FILE *file;

  while ((file = fopen_watched(io_path, "rb")) == NULL && errno != EWOULDBLOCK &&
         retry_count < max_retries) {
    usleep(1000 * (retry_count + 1));
    retry_count++;
  }
  if (!file && errno == EWOULDBLOCK) {
    return -2; // Leased by another process: run_diff() says so
  }
  if (!file) {
    fprintf(stderr, RED "Cannot open %s: %s\n" RESET, shown_name(filename),
            strerror(errno));
    return -1;
  }

  unsigned char buffer[65536];
  size_t bytes_read, total = 0;
  int binary = 0;
  while (!binary && total < CACHE_MAX_BYTES &&
         (bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
    binary = memchr(buffer, 0, bytes_read) != NULL;
    total += bytes_read;
    if ((total & ((1 << 20) - 1)) < sizeof(buffer)) {
      stop_if_signalled();
    }
  }
  fclose(file);
  return binary;
}

void print_bin_diff(const char *path, const char *io_path,
                    const char *cached_path, const char *log_file) {
  FILE *f1 = fopen_watched(io_path, "rb");
  FILE *f2 = fopen_cache(cached_path);

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
  size_t next_signal_check = 1 << 20;
  int differences = 0;
  int continue_reading = 1;

  while (continue_reading) {
    // Leave if a signal is waiting, every MiB compared
    if (offset >= next_signal_check) {
      stop_if_signalled();
      next_signal_check = offset + (1 << 20);
    }
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
  FILE *log_fp = log_file ? log_begin() : NULL;
  if (!log_fp)
    return;

  time_t now = time(NULL);
  char *timestamp = ctime(&now);
  if (timestamp) {
    size_t tlen = strlen(timestamp);
    if (tlen > 0 && timestamp[tlen - 1] == '\n') {
      timestamp[tlen - 1] = '\0';
    }
  } else {
    timestamp = "(unknown time)";
  }

  fprintf(log_fp, "\n=== Binary File Diff ===\n");
  fprintf(log_fp, "Time: %s\n", timestamp);
  fprintf(log_fp, "File: %s\n", shown_name(path));
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
  log_end();
}

// cached_file_path is the watched file's own cache entry
void run_diff(const char *path, const char *io_path, const char *cached_file_path,
              const char *event_type, int verbose, const char *log_file) {
  char why[192];

  // A file too large for the cache has only its size and time kept there
  off_t kept_size;
  struct timespec kept_mtime;
  struct stat st;
  int stub = cache_stub(cached_file_path, &kept_size, &kept_mtime);
  if (stub > 0 || (stat(io_path, &st) == 0 && st.st_size > CACHE_MAX_BYTES)) {
    if (cache_differs(io_path, cached_file_path)) {
      if (stub == STUB_BUDGET) {
        snprintf(why, sizeof(why), "not diffed (the cache is full, %d MiB for all files: only its size and modification time are compared)",
                 CACHE_BUDGET_BYTES >> 20);
      } else {
        snprintf(why, sizeof(why), "too large to diff (over the %d MiB cache limit: only its size and modification time are compared)",
                 CACHE_MAX_BYTES >> 20);
      }
      report_change(path, event_type, log_file, why);
      if (copy_file(io_path, cached_file_path, path) != 0) {
        fprintf(stderr, RED "Failed to update the cache of %s\n" RESET, shown_name(path));
      }
    }
    return;
  }

  // Check if file is binary
  int bin_check = is_binary_file(path, io_path);
  if (bin_check > 0) {
    if (verbose) {
      printf(DARK_GREY "Binary file detected: %s\n" RESET, shown_name(path));
      print_bin_diff(path, io_path, cached_file_path, log_file);
    }

    // Still update the cache for binary files
    if (copy_file(io_path, cached_file_path, path) != 0) {
      fprintf(stderr, RED "Failed to update the cache of %s\n" RESET,
              shown_name(path));
    }

    return;
  } else if (bin_check == -2) {
    fprintf(stderr, RED "+ Skipping %s this time: another process holds a lease on it\n" RESET,
            shown_name(path));
    return;
  } else if (bin_check < 0) {
    fprintf(stderr, RED "Failed to read %s.\n" RESET, shown_name(path));
    return;
  }

  int current_why, cached_why = READ_OK;
  long long current_size = 0, cached_size = 0;
  file_lines current = read_file_lines(path, io_path, 0, &current_why, &current_size);
  file_lines cached = {NULL, NULL, 0};
  if (current_why != READ_LEASED) {
    cached = read_file_lines(path, cached_file_path, 1, &cached_why, &cached_size);
  }

  // A side skipped for a lease was not read: it is neither empty nor changed
  if (current_why == READ_LEASED || cached_why == READ_LEASED) {
    free_file_lines(&current);
    free_file_lines(&cached);
    return;
  }

  // Too large to diff line by line: only say whether it changed
  if (current_why != READ_OK || cached_why != READ_OK) {
    if (cache_differs(io_path, cached_file_path)) {
      if (current_why == READ_TOO_MANY_LINES || cached_why == READ_TOO_MANY_LINES) {
        snprintf(why, sizeof(why), "too large to diff (%lld lines; the limit is %d)",
                 current_why == READ_TOO_MANY_LINES ? current_size : cached_size,
                 DIFF_MAX_LINES);
      } else {
        snprintf(why, sizeof(why), "too large to diff (%lld bytes; the limit is %d MiB)",
                 current_why == READ_TOO_LARGE ? current_size : cached_size,
                 DIFF_MAX_BYTES >> 20);
      }
      report_change(path, event_type, log_file, why);
      if (copy_file(io_path, cached_file_path, path) != 0) {
        fprintf(stderr, RED "Failed to update the cache of %s\n" RESET, shown_name(path));
      }
    }
    free_file_lines(&current);
    free_file_lines(&cached);
    return;
  }

  // First check if either file is empty
  if (!current.data || !cached.data) {
    if (!current.data && cached.data) {
      // File was emptied
      printf(RED "- File emptied\n" RESET);
      if (log_file) {
        diff_hunk all = {0, cached.count, 0, 0};
        log_changes(log_file, path, "Emptied", &current, &cached, &all, 1);
      }
    } else if (current.data && !cached.data) {
      // New content added to empty file
      printf(GREEN "+ New content added\n" RESET);
      if (log_file) {
        diff_hunk all = {0, 0, 0, current.count};
        log_changes(log_file, path, "New content", &current, &cached, &all, 1);
      }
    }

    // Update cache regardless of which case
    if (copy_file(io_path, cached_file_path, path) != 0) {
      fprintf(stderr, RED "Failed to update the cache of %s\n" RESET,
              shown_name(path));
    }
  }

  // Both files have content, proceed with normal diff
  if (current.data && cached.data) {
    diff_hunk *hunks;
    int count;
    int changed;
    if (diff_lines(&current, &cached, &hunks, &count) != 0) {
      snprintf(why, sizeof(why), "in too many places to show line by line: the whole file is reported as changed (%d lines, %d before)",
               current.count, cached.count);
      report_change(path, event_type, log_file, why);
      changed = 1;
    } else {
      // Print the changes
      print_diff(&current, &cached, hunks, count, verbose);
      changed = count > 0;
      if (changed && log_file) {
        log_changes(log_file, path, event_type, &current, &cached, hunks, count);
      }
    }
    free(hunks);

    if (changed) {
      // Update the cache file with the current content
      if (copy_file(io_path, cached_file_path, path) != 0) {
        fprintf(stderr, RED "Failed to update the cache of %s\n" RESET,
                shown_name(path));
      }
    }
  }

  // Cleanup
  free_file_lines(&current);
  free_file_lines(&cached);
}
