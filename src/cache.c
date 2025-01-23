#include "cache.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int copy_file(const char *src, const char *dest) {
  struct stat statbuf;

  // Check if the destination is a directory
  if (stat(dest, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
    fprintf(stderr, "Failed to open destination file: %s is a directory\n",
            dest);
    return -1;
  }

  int src_fd = open(src, O_RDONLY);
  if (src_fd < 0) {
    perror("Failed to open source file");
    return -1;
  }

  int dest_fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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
      snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

      struct stat statbuf;
      if (stat(full_path, &statbuf) == 0) {
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

void create_caches(int max_files, const char *cache_dir, char *watch_paths[],
                   char *cached_paths[], int verbose) {
  if (!cache_dir || !watch_paths || !cached_paths) {
    return;
  }

  // Create cache directory if it doesn't exist
  struct stat st;
  if (stat(cache_dir, &st) != 0) {
    if (mkdir(cache_dir, 0755) != 0) {
      perror("Failed to create cache directory");
      return;
    }
  }

  // For each watched path, create a cache file
  for (int i = 0; i < max_files; i++) {
    if (watch_paths[i] != NULL) {
      char dest_path[PATH_MAX];
      snprintf(dest_path, sizeof(dest_path), "%s/%s", cache_dir,
               basename(watch_paths[i]));

      if (copy_file(watch_paths[i], dest_path) == 0) {
        cached_paths[i] = strdup(dest_path);
        if (verbose) {
          printf(DARK_GREY "+ Cached [%d]: %s -> %s\n" RESET, i, watch_paths[i],
                 dest_path);
        }
      }
    }
  }
}

void create_cache_for_file(const char *path, const char *cache_dir,
                          char **cached_path, int verbose) {
    if (!path || !cache_dir || !cached_path) {
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
    if (stat(cache_path, &cache_stat) != 0) {
        if (copy_file(path, cache_path) == 0) {
            if (verbose) {
                printf(DARK_GREY "+ Cached: %s -> %s\n" RESET, path, cache_path);
            }
        }
    }
    
    free(path_copy);
}
