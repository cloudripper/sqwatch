#define _GNU_SOURCE  // O_PATH
#include "cache.h"
#include "sqwatch.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int cache_dir_owned = 0;

// The cache directory as create_caches() checked it. Cache files are reached
// beneath this descriptor, never through the cache path again, so a directory
// put in its place later is not used
int cache_dir_fd = -1;

// A cache file is shown as <cache_dir>/<name>; this is its name
static const char *cache_name(const char *path) {
  const char *slash = strrchr(path, '/');
  return slash ? slash + 1 : path;
}

// Open a file in the cache directory: a symlink planted under the name is not
// followed, and O_NONBLOCK keeps a FIFO from blocking the open. Anything but a
// regular file is refused. A cache file holds a copy of a watched file, so one
// opened for writing is made readable by its owner only. O_TRUNC is applied
// only once the file has passed those checks. A file the user does not own, or
// one with another name (a hard link), is not read or written; a write first
// replaces it, and one the user may not write, with a new file of the user's
int open_cache_file(const char *path, int flags) {
  const char *name = cache_name(path);
  int writing = (flags & O_ACCMODE) != O_RDONLY;
  struct stat st;
  if (writing && fstatat(cache_dir_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
      S_ISREG(st.st_mode) &&
      (st.st_uid != geteuid() || st.st_nlink != 1 || !(st.st_mode & S_IWUSR))) {
    if (unlinkat(cache_dir_fd, name, 0) != 0) {
      return -1;
    }
    flags |= O_CREAT | O_EXCL;
  }
  int fd = openat(cache_dir_fd, name, (flags & ~O_TRUNC) | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                  0600);
  if (fd < 0) {
    return -1;
  }

  int ok = fstat(fd, &st) == 0;
  if (ok && !S_ISREG(st.st_mode)) {
    errno = EINVAL;
    ok = 0;
  }
  if (ok && (st.st_uid != geteuid() || st.st_nlink != 1)) {
    errno = EPERM;
    ok = 0;
  }
  if (ok && writing) {
    ok = fchmod(fd, 0600) == 0;
  }
  if (ok && (flags & O_TRUNC)) {
    ok = ftruncate(fd, 0) == 0;
  }
  if (!ok) {
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
  return fd;
}

int copy_file(const char *src, const char *dest) {
  struct stat statbuf;

  // Check if the destination is a directory
  if (fstatat(cache_dir_fd, cache_name(dest), &statbuf, AT_SYMLINK_NOFOLLOW) == 0 &&
      S_ISDIR(statbuf.st_mode)) {
    fprintf(stderr, "Failed to open destination file: %s is a directory\n",
            dest);
    return -1;
  }

  int src_fd = open(src, O_RDONLY);
  if (src_fd < 0) {
    perror("Failed to open source file");
    return -1;
  }

  // The cache file name comes from the watched tree; never write through a
  // symlink planted under that name
  int dest_fd = open_cache_file(dest, O_WRONLY | O_CREAT | O_TRUNC);
  if (dest_fd < 0) {
    perror("Failed to open destination file");
    close(src_fd);

    return -1;
  }

  char buffer[4096];
  ssize_t bytes_read;
  while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
    ssize_t result = write(dest_fd, buffer, bytes_read);
    if (result < 0) {
      perror("Failed to write to destination file");
      close(src_fd);
      close(dest_fd);
      return -1;
    }
  }

  close(src_fd);
  close(dest_fd);
  return 0;
}

void remove_directory(const char *path) {
  DIR *dir = opendir(path);
  if (dir) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
        continue;
      }

      char full_path[PATH_MAX];
      if (snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name) >= (int)sizeof(full_path)) {
        fprintf(stderr, RED "Path too long, not removing %s/%s\n" RESET, path, entry->d_name);
        continue;
      }

      struct stat statbuf;
      if (lstat(full_path, &statbuf) == 0) {
        if (S_ISDIR(statbuf.st_mode)) {
          remove_directory(full_path);
        } else {
          unlink(full_path);
        }
      }
    }
    closedir(dir);
    rmdir(path);
  }
}

int unlink_cache_file(const char *path) {
  return unlinkat(cache_dir_fd, cache_name(path), 0);
}

// Set up the cache directory. Returns 0 if it can be used, -1 otherwise. The
// cache holds copies of the watched files, so a directory that is not the
// user's own, or that others can write to, is refused. It is checked through
// the descriptor every later cache access goes through. The watched files are
// copied in by cache_watched_files()
int create_caches(const char *cache_dir) {
  if (!cache_dir) {
    return -1;
  }

  int created = mkdir(cache_dir, 0700) == 0;
  if (!created && errno != EEXIST) {
    perror("Failed to create cache directory");
    return -1;
  }

  struct stat st;
  const char *reason = NULL;
  int fd = open(cache_dir, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 || fstat(fd, &st) != 0) {
    reason = errno == ENOTDIR ? "it is not a directory" : strerror(errno);
  } else if (st.st_uid != geteuid()) {
    reason = "it is owned by another user";
  } else if (st.st_mode & (S_IWGRP | S_IWOTH)) {
    reason = "other users can write to it";
  }

  char shown[PATH_MAX];
  if (reason) {
    fprintf(stderr, RED "+ Not using cache directory %s: %s\n" RESET,
            printable(cache_dir, shown, sizeof(shown)), reason);
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }

  cache_dir_fd = fd;
  cache_dir_owned = created;
  if (!created) {
    fprintf(stderr, DARK_GREY "+ Cache directory %s already exists; it will not be removed on exit\n" RESET,
            printable(cache_dir, shown, sizeof(shown)));
  }
  return 0;
}

// path names the file in messages and gives the cache file its name; the
// content is read through io_path
void create_cache_for_file(const char *path, const char *io_path, const char *cache_dir,
                          char **cached_path, int verbose) {
    if (!path || !io_path || !cache_dir || !cached_path) {
        return;
    }

    char *path_copy = strdup(path);
    if (!path_copy) {
        return;
    }

    char *base = basename(path_copy);
    char cache_path[PATH_MAX];
    snprintf(cache_path, sizeof(cache_path), "%s/%s", cache_dir, base);

    // Always update the cached_path pointer
    *cached_path = strdup(cache_path);

    // Only copy the file if it doesn't exist in cache
    struct stat cache_stat;
    if (fstatat(cache_dir_fd, base, &cache_stat, AT_SYMLINK_NOFOLLOW) != 0) {
        if (copy_file(io_path, cache_path) == 0) {
            if (verbose) {
                printf(DARK_GREY "+ Cached: %s -> %s\n" RESET, path, cache_path);
            }
        }
    }

    free(path_copy);
}
