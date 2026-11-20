#define _GNU_SOURCE  // O_PATH
#include "cache.h"
#include "sqwatch.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <linux/magic.h>
#include <pwd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef EXFAT_SUPER_MAGIC
#define EXFAT_SUPER_MAGIC 0x2011BAB0
#endif
#ifndef NTFS_SB_MAGIC
#define NTFS_SB_MAGIC 0x5346544e
#endif
#ifndef V9FS_MAGIC
#define V9FS_MAGIC 0x01021997
#endif
#ifndef CEPH_SUPER_MAGIC
#define CEPH_SUPER_MAGIC 0x00c36400
#endif
#ifndef AFS_SUPER_MAGIC
#define AFS_SUPER_MAGIC 0x5346414F
#endif
#ifndef AFS_FS_MAGIC
#define AFS_FS_MAGIC 0x6B414653
#endif

int cache_dir_owned = 0;

// The cache directory as create_caches() checked it. Cache files are reached
// beneath this descriptor, never through the cache path again, so a directory
// put in its place later is not used
int cache_dir_fd = -1;
// The checked parent of the cache directory, and the directory's name in it
static int cache_parent_fd = -1;
static char cache_leaf[PATH_MAX];

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

int unlink_cache_file(const char *path) {
  return unlinkat(cache_dir_fd, cache_name(path), 0);
}

// The owner trusted as root: 0, unless / reports the overflow uid, as it does
// in a user namespace where root is not mapped. Inside such a namespace every
// unmapped owner looks the same, so all of them are then trusted like root
static uid_t root_uid = 0;

static uid_t root_owner(const struct stat *root) {
  unsigned long overflow = 65534;
  FILE *f = fopen("/proc/sys/kernel/overflowuid", "r");
  if (f) {
    if (fscanf(f, "%lu", &overflow) != 1) {
      overflow = 65534;
    }
    fclose(f);
  }
  return root->st_uid == overflow ? root->st_uid : 0;
}

// Debian OpenSSH's user-group-modes rule: a group named after the owner, with
// no other members, that is the owner's primary group and no one else's does
// not let anyone else write. The name must match because the scan of users
// below can miss some: with SSSD or LDAP and enumeration off, getpwent() lists
// local users only, and a shared primary group such as "Domain Users" with no
// listed members would otherwise pass
static int private_group(uid_t uid, gid_t gid) {
  struct passwd *pw = getpwuid(uid);
  if (!pw || pw->pw_gid != gid) {
    return 0;
  }
  struct group *gr = getgrgid(gid);
  if (!gr || gr->gr_mem[0] || strcmp(gr->gr_name, pw->pw_name) != 0) {
    return 0;
  }
  int alone = 1;
  setpwent();
  while (alone && (pw = getpwent()) != NULL) {
    alone = pw->pw_gid != gid || pw->pw_uid == uid;
  }
  endpwent();
  return alone;
}

// With an access ACL the group bits are the ACL mask, so named users or
// groups may be able to write. 1 if fd has one, or if that cannot be told
static int has_access_acl(int fd) {
  char proc_path[32];
  snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
  if (getxattr(proc_path, "system.posix_acl_access", NULL, 0) >= 0) {
    return 1;
  }
  // A filesystem without ACLs reports ENOTSUP: it cannot have one either
  return errno != ENODATA && errno != ENOTSUP;
}

// Whether users other than the owner can write in the directory fd refers to.
// Group write counts unless the group is the owner's private group, never for
// group 0, and never when an ACL may give it to others
static int others_can_write(int fd, const struct stat *st) {
  if (st->st_mode & S_IWOTH) {
    return 1;
  }
  if (!(st->st_mode & S_IWGRP)) {
    return 0;
  }
  return st->st_gid == 0 || has_access_acl(fd) || !private_group(st->st_uid, st->st_gid);
}

// Why owners on the filesystem fd is on cannot be trusted; NULL if they can
static const char *untrusted_fs(int fd) {
  struct statfs sfs;
  if (fstatfs(fd, &sfs) != 0) {
    return "its filesystem cannot be identified";
  }
  switch (sfs.f_type) {
  case FUSE_SUPER_MAGIC:
    return "on a FUSE filesystem, which reports any owner";
  case NFS_SUPER_MAGIC:
  case SMB_SUPER_MAGIC:
  case CIFS_SUPER_MAGIC:
  case SMB2_SUPER_MAGIC:
  case V9FS_MAGIC:
  case CEPH_SUPER_MAGIC:
  case AFS_SUPER_MAGIC:
  case AFS_FS_MAGIC:
    return "on a network filesystem, whose server reports the owners";
  case MSDOS_SUPER_MAGIC:
  case EXFAT_SUPER_MAGIC:
  case NTFS_SB_MAGIC:
    return "on a FAT or NTFS filesystem, whose owners come from mount options";
  }
  return NULL;
}

// Why a directory on the way to the cache directory, or a symlink met there,
// cannot be trusted; NULL if it can. As in OpenSSH's secure_path(), only root
// and the user may own one, and a directory others can write to must be sticky
static const char *untrusted(int fd, const struct stat *st) {
  if (st->st_uid != root_uid && st->st_uid != geteuid()) {
    return "owned by another user";
  }
  if (S_ISDIR(st->st_mode) && others_can_write(fd, st) && !(st->st_mode & S_ISVTX)) {
    return "other users can write to it and it is not sticky";
  }
  if (!S_ISDIR(st->st_mode) && !S_ISLNK(st->st_mode)) {
    return "not a directory";
  }
  return untrusted_fs(fd);
}

// Open the directory an absolute path names. Every component is opened beneath
// the one before without following it and checked with untrusted(), from /
// down; a symlink that passes is followed by resolving its target the same way.
// On failure, where names the component at fault and *why says what is wrong
static int open_trusted_dir(const char *path, char *where, size_t size, const char **why) {
  char todo[PATH_MAX];
  char name[NAME_MAX + 1];
  const char *rest = path;
  int hops = 0;
  struct stat st;
  int fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);

  snprintf(where, size, "/");
  if (fd < 0 || fstat(fd, &st) != 0) {
    *why = strerror(errno);
  } else {
    root_uid = root_owner(&st);
    *why = untrusted(fd, &st);
  }

  while (!*why && *rest) {
    size_t len = strcspn(rest, "/");
    const char *next = rest + len + strspn(rest + len, "/");
    if (len == 0 || (len == 1 && *rest == '.')) {
      rest = next;
      continue;
    }
    snprintf(name, sizeof(name), "%.*s", (int)len, rest);
    rest = next;

    errno = ENAMETOOLONG;
    int sub = len > NAME_MAX ? -1 : openat(fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (sub < 0 || fstat(sub, &st) != 0) {
      *why = strerror(errno);
    } else if ((*why = untrusted(sub, &st)) == NULL && S_ISLNK(st.st_mode)) {
      // Go on from the target: from / if it is absolute, else from here
      char target[PATH_MAX];
      char joined[PATH_MAX];
      ssize_t n = -1;
      errno = ELOOP;
      if (++hops <= 40) {
        n = readlinkat(sub, "", target, sizeof(target) - 1);
      }
      if (n >= 0) {
        target[n] = '\0';
        errno = ENAMETOOLONG;
        if (snprintf(joined, sizeof(joined), "%s/%s", target, rest) >= (int)sizeof(joined)) {
          n = -1;
        }
      }
      if (n < 0) {
        *why = strerror(errno);
      } else {
        strcpy(todo, joined);
        rest = todo;
        if (target[0] == '/') {
          close(fd);
          fd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
          *why = fd < 0 ? strerror(errno) : NULL;
        }
        close(sub);
        continue;
      }
    }

    if (*why) {
      char proc_path[32];
      char dir[PATH_MAX];
      snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
      ssize_t n = readlink(proc_path, dir, sizeof(dir) - 1);
      dir[n > 1 ? n : 0] = '\0';
      snprintf(where, size, "%s/%s", dir, name);
      if (sub >= 0) {
        close(sub);
      }
      break;
    }
    close(fd);
    fd = sub;
  }

  if (*why) {
    if (fd >= 0) {
      close(fd);
    }
    return -1;
  }
  return fd;
}

// A directory stream on the directory dir_fd refers to, which may be O_PATH
static DIR *open_dir_stream(int dir_fd) {
  int fd = openat(dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  DIR *dir = fd < 0 ? NULL : fdopendir(fd);
  if (fd >= 0 && !dir) {
    close(fd);
  }
  return dir;
}

static int dir_is_empty(int dir_fd) {
  DIR *dir = open_dir_stream(dir_fd);
  struct dirent *entry;
  int empty = dir != NULL;
  while (empty && (entry = readdir(dir)) != NULL) {
    empty = strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0;
  }
  if (dir) {
    closedir(dir);
  }
  return empty;
}

// Remove everything in the directory fd refers to, and close fd. Each entry is
// reached from its own directory's descriptor and a symlink is never followed,
// so nothing outside the directory can be reached. One descriptor per level
static void empty_directory_fd(int fd) {
  DIR *dir = fdopendir(fd);
  if (!dir) {
    close(fd);
    return;
  }
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }
    int sub = openat(dirfd(dir), entry->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sub >= 0) {
      empty_directory_fd(sub);
      unlinkat(dirfd(dir), entry->d_name, AT_REMOVEDIR);
    } else {
      unlinkat(dirfd(dir), entry->d_name, 0);
    }
  }
  closedir(dir);
}

static void empty_directory(int dir_fd) {
  int fd = openat(dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd >= 0) {
    empty_directory_fd(fd);
  }
}

static int refuse_cache_dir(const char *cache_dir, const char *where, const char *reason) {
  char shown[PATH_MAX];
  char shown_where[PATH_MAX];
  if (where) {
    fprintf(stderr, RED "+ Not using cache directory %s: %s: %s\n" RESET,
            printable(cache_dir, shown, sizeof(shown)),
            printable(where, shown_where, sizeof(shown_where)), reason);
  } else {
    fprintf(stderr, RED "+ Not using cache directory %s: %s\n" RESET,
            printable(cache_dir, shown, sizeof(shown)), reason);
  }
  return -1;
}

// Set up the cache directory. Returns 0 if it can be used, -1 otherwise. The
// cache holds copies of the watched files, so a directory that is not the
// user's own, or that others can write to, is refused. Its parent is opened
// with open_trusted_dir() and the directory is made and opened beneath it, by
// name. It is checked through the descriptor every later cache access goes
// through. The watched files are copied in by cache_watched_files()
int create_caches(const char *cache_dir) {
  if (!cache_dir) {
    return -1;
  }

  // The last component has to be a name in the parent: a trailing "/" or
  // "/." would make the kernel follow a symlink there
  char path[PATH_MAX];
  int len = snprintf(path, sizeof(path), "%s", cache_dir);
  if (len >= (int)sizeof(path)) {
    return refuse_cache_dir(cache_dir, NULL, strerror(ENAMETOOLONG));
  }
  while (len > 1 && path[len - 1] == '/') {
    path[--len] = '\0';
  }
  char *slash = strrchr(path, '/');
  const char *leaf = slash ? slash + 1 : path;
  if (*leaf == '\0' || strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0) {
    return refuse_cache_dir(cache_dir, NULL, "the path must end in a directory name");
  }

  // A relative path is checked from / down too
  char parent[PATH_MAX];
  char cwd[PATH_MAX];
  if (slash) {
    *slash = '\0';
  }
  if (cache_dir[0] == '/') {
    len = snprintf(parent, sizeof(parent), "/%s", path);
  } else if (getcwd(cwd, sizeof(cwd))) {
    len = snprintf(parent, sizeof(parent), "%s/%s", cwd, slash ? path : "");
  } else {
    return refuse_cache_dir(cache_dir, NULL, errno == ERANGE ?
                            "the current directory path is too long" : strerror(errno));
  }
  if (len >= (int)sizeof(parent)) {
    return refuse_cache_dir(cache_dir, NULL, strerror(ENAMETOOLONG));
  }

  char where[PATH_MAX];
  const char *reason = NULL;
  int parent_fd = open_trusted_dir(parent, where, sizeof(where), &reason);
  if (parent_fd < 0) {
    return refuse_cache_dir(cache_dir, where, reason);
  }

  int created = mkdirat(parent_fd, leaf, 0700) == 0;
  if (!created && errno != EEXIST) {
    perror("Failed to create cache directory");
    close(parent_fd);
    return -1;
  }

  struct stat st;
  int fd = openat(parent_fd, leaf, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0 || fstat(fd, &st) != 0) {
    reason = errno == ENOTDIR ? "it is not a directory" : strerror(errno);
  } else if (st.st_uid != geteuid()) {
    reason = "it is owned by another user";
  } else if (others_can_write(fd, &st)) {
    reason = "other users can write to it";
  } else {
    reason = untrusted_fs(fd);
  }

  if (reason) {
    if (fd >= 0) {
      close(fd);
    }
    close(parent_fd);
    return refuse_cache_dir(cache_dir, NULL, reason);
  }

  cache_dir_fd = fd;
  cache_parent_fd = parent_fd;
  snprintf(cache_leaf, sizeof(cache_leaf), "%s", leaf);
  // Only a directory this run made, and found empty, is removed on exit
  cache_dir_owned = created && dir_is_empty(fd);
  if (!cache_dir_owned) {
    char shown[PATH_MAX];
    fprintf(stderr, DARK_GREY "+ Cache directory %s already exists; it will not be removed on exit\n" RESET,
            printable(cache_dir, shown, sizeof(shown)));
  }
  return 0;
}

// Remove the cache directory this run made: its contents beneath the
// descriptor it was checked through, then its name in the checked parent, and
// that only while the name still refers to the same directory
void remove_caches(void) {
  struct stat named, pinned;
  empty_directory(cache_dir_fd);
  if (fstatat(cache_parent_fd, cache_leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
      fstat(cache_dir_fd, &pinned) == 0 &&
      named.st_dev == pinned.st_dev && named.st_ino == pinned.st_ino) {
    unlinkat(cache_parent_fd, cache_leaf, AT_REMOVEDIR);
  }
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
