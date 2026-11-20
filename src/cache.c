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
#include <signal.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
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

// This run's own directory inside the cache directory, run.<16 random hex
// digits>, made by create_caches(). Cache entries are made and reached beneath
// this descriptor, never through a path again, so a directory put in its
// place later is not used, and nothing another run or an earlier one left in
// the cache directory is ever read
int cache_dir_fd = -1;
static char run_name[32];
// The cache directory as create_caches() checked it, its checked parent and
// its name in that parent
static int cache_top_fd = -1;
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

// Open a watched file to read it. With O_NONBLOCK the open fails with
// EWOULDBLOCK instead of waiting while another process holds a lease on the
// file; the caller skips the file this time
int open_watched_file(const char *io_path) {
  int fd = open(io_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd >= 0) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
  }
  return fd;
}

// Whether the cache entry path holds only the size and modification time of
// a watched file too large to copy (see copy_file()): such an entry is the
// only one made read-only. Returns 1 and fills size and mtime if so, 0 if it
// holds a copy, -1 if it cannot be read
int cache_stub(const char *path, off_t *size, struct timespec *mtime) {
  int fd = open_cache_file(path, O_RDONLY);
  struct stat st;
  if (fd < 0) {
    return -1;
  }
  int stub = fstat(fd, &st) != 0 ? -1 : !(st.st_mode & S_IWUSR);
  if (stub == 1) {
    char record[96];
    ssize_t n = read(fd, record, sizeof(record) - 1);
    long long bytes = -1, sec = 0;
    long nsec = 0;
    record[n > 0 ? n : 0] = '\0';
    if (sscanf(record, "%lld %lld %ld", &bytes, &sec, &nsec) != 3) {
      bytes = -1;  // Never equal to a real size
    }
    if (size) {
      *size = (off_t)bytes;
    }
    if (mtime) {
      mtime->tv_sec = (time_t)sec;
      mtime->tv_nsec = nsec;
    }
  }
  close(fd);
  return stub;
}

// Make the open cache entry dest_fd hold only the size and modification time
// of the watched file src_fd, and make it read-only, which marks it so
static int write_stub(int dest_fd, int src_fd) {
  struct stat st;
  char record[96];
  if (fstat(src_fd, &st) != 0) {
    return -1;
  }
  int len = snprintf(record, sizeof(record), "%lld %lld %ld\n", (long long)st.st_size,
                     (long long)st.st_mtim.tv_sec, (long)st.st_mtim.tv_nsec);
  if (ftruncate(dest_fd, 0) != 0 || pwrite(dest_fd, record, len, 0) != len ||
      fchmod(dest_fd, 0400) != 0) {
    return -1;
  }
  return 0;
}

// Copy the watched file src into the cache entry dest; shown names the watched
// file in messages. When the copy fails the entry is removed, so that a part
// of a copy is never read as the file's. A file larger than CACHE_MAX_BYTES is
// not copied: the entry keeps its size and modification time (see
// cache_stub()), and a notice says so when that starts. A sparse file counts
// by its size, so its holes are never written out
int copy_file(const char *src, const char *dest, const char *shown_path) {
  struct stat statbuf;

  // Check if the destination is a directory
  if (fstatat(cache_dir_fd, cache_name(dest), &statbuf, AT_SYMLINK_NOFOLLOW) == 0 &&
      S_ISDIR(statbuf.st_mode)) {
    fprintf(stderr, "Failed to open the cache of %s: it is a directory\n",
            shown_name(shown_path));
    return -1;
  }
  int was_stub = cache_stub(dest, NULL, NULL) == 1;

  int src_fd = open_watched_file(src);
  if (src_fd < 0) {
    if (errno == EWOULDBLOCK) {
      fprintf(stderr, RED "+ Not updating the cache of %s this time: another process holds a lease on it\n" RESET,
              shown_name(shown_path));
    } else {
      perror("Failed to open source file");
    }
    unlink_cache_file(dest);
    return -1;
  }

  // The cache file name comes from the watched tree; never write through a
  // symlink planted under that name
  int dest_fd = open_cache_file(dest, O_WRONLY | O_CREAT | O_TRUNC);
  if (dest_fd < 0) {
    perror("Failed to open destination file");
    close(src_fd);
    unlink_cache_file(dest);
    return -1;
  }

  struct stat src_st;
  int too_large = fstat(src_fd, &src_st) == 0 && src_st.st_size > CACHE_MAX_BYTES;
  char buffer[65536];
  ssize_t bytes_read = 0;
  off_t total = 0;
  while (!too_large && (bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
    stop_if_signalled();
    if (total + bytes_read > CACHE_MAX_BYTES) {
      too_large = 1;  // It grew while being copied
      break;
    }
    for (ssize_t done = 0; done < bytes_read;) {
      ssize_t result = write(dest_fd, buffer + done, bytes_read - done);
      if (result <= 0) {
        perror("Failed to write to destination file");
        close(src_fd);
        close(dest_fd);
        unlink_cache_file(dest);
        return -1;
      }
      done += result;
    }
    total += bytes_read;
  }
  if (too_large) {
    if (write_stub(dest_fd, src_fd) != 0) {
      perror("Failed to write to destination file");
      close(src_fd);
      close(dest_fd);
      unlink_cache_file(dest);
      return -1;
    }
    if (!was_stub) {
      fprintf(stderr, DARK_GREY "+ Not keeping a copy of %s: it is over the %d MiB cache limit; only its size and modification time are kept\n" RESET,
              shown_name(shown_path), CACHE_MAX_BYTES >> 20);
    }
  }

  close(src_fd);
  close(dest_fd);
  return 0;
}

// Whether the watched file read through io_path differs from the cache entry
// path: 1 if it does or either cannot be read, 0 if they are the same. An
// entry that kept only the size and modification time compares those
int cache_differs(const char *io_path, const char *path) {
  off_t stub_size;
  struct timespec stub_mtime;
  int stub = cache_stub(path, &stub_size, &stub_mtime);
  int src_fd = stub < 0 ? -1 : open_watched_file(io_path);
  int cache_fd = src_fd < 0 || stub ? -1 : open_cache_file(path, O_RDONLY);
  struct stat src_st, cache_st;
  int differs = src_fd < 0 || fstat(src_fd, &src_st) != 0;
  if (!differs && stub) {
    differs = src_st.st_size != stub_size || src_st.st_mtim.tv_sec != stub_mtime.tv_sec ||
              src_st.st_mtim.tv_nsec != stub_mtime.tv_nsec;
  } else if (!differs) {
    differs = cache_fd < 0 || fstat(cache_fd, &cache_st) != 0 ||
              src_st.st_size != cache_st.st_size;
  }
  while (!differs && !stub) {
    char a[65536], b[sizeof(a)];
    ssize_t n = read(src_fd, a, sizeof(a));
    if (n <= 0) {
      differs = n < 0;
      break;
    }
    ssize_t got = 0, m = 0;
    while (got < n && (m = read(cache_fd, b + got, n - got)) > 0) {
      got += m;
    }
    differs = got != n || memcmp(a, b, n) != 0;
    stop_if_signalled();
  }
  if (src_fd >= 0) {
    close(src_fd);
  }
  if (cache_fd >= 0) {
    close(cache_fd);
  }
  return differs;
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

// Say why the path given for what ("cache directory", "log file") is not used
static int refuse_path(const char *what, const char *path, const char *where, const char *reason) {
  if (where) {
    fprintf(stderr, RED "+ Not using %s %s: %s: %s\n" RESET, what,
            shown_name(path),
            shown_name(where), reason);
  } else {
    fprintf(stderr, RED "+ Not using %s %s: %s\n" RESET, what,
            shown_name(path), reason);
  }
  return -1;
}

// Open the directory that is to hold the last component of path with
// open_trusted_dir(), and point *leaf at that component, copied into buf. The
// last component has to be a name in the parent: a trailing "/" or "/." would
// make the kernel follow a symlink there. A trailing "/" is dropped from a
// directory's path and refused in a file's (is_dir 0). A relative path is
// checked from / down too. Returns the parent's descriptor, or -1 once it has
// said why
static int open_trusted_parent(const char *what, const char *path, int is_dir, char *buf,
                               size_t size, const char **leaf) {
  int len = snprintf(buf, size, "%s", path);
  if (len >= (int)size) {
    return refuse_path(what, path, NULL, strerror(ENAMETOOLONG));
  }
  if (!is_dir && len > 0 && buf[len - 1] == '/') {
    return refuse_path(what, path, NULL, "the path must end in a file name");
  }
  while (len > 1 && buf[len - 1] == '/') {
    buf[--len] = '\0';
  }
  char *slash = strrchr(buf, '/');
  *leaf = slash ? slash + 1 : buf;
  if (**leaf == '\0' || strcmp(*leaf, ".") == 0 || strcmp(*leaf, "..") == 0) {
    return refuse_path(what, path, NULL, is_dir ? "the path must end in a directory name" :
                                                  "the path must end in a file name");
  }

  char parent[PATH_MAX];
  char cwd[PATH_MAX];
  if (slash) {
    *slash = '\0';
  }
  if (path[0] == '/') {
    len = snprintf(parent, sizeof(parent), "/%s", buf);
  } else if (getcwd(cwd, sizeof(cwd))) {
    len = snprintf(parent, sizeof(parent), "%s/%s", cwd, slash ? buf : "");
  } else {
    return refuse_path(what, path, NULL, errno == ERANGE ?
                       "the current directory path is too long" : strerror(errno));
  }
  if (len >= (int)sizeof(parent)) {
    return refuse_path(what, path, NULL, strerror(ENAMETOOLONG));
  }

  char where[PATH_MAX];
  const char *reason = NULL;
  int parent_fd = open_trusted_dir(parent, where, sizeof(where), &reason);
  if (parent_fd < 0) {
    return refuse_path(what, path, where, reason);
  }
  return parent_fd;
}

// Set up the cache directory. Returns 0 if it can be used, -1 otherwise. The
// cache holds copies of the watched files, so a directory that is not the
// user's own, or that others can write to, is refused. Its parent is opened
// with open_trusted_parent() and the directory is made and opened beneath it,
// by name, and checked through that descriptor. Inside it this run makes a
// directory of its own, which every later cache access goes through and which
// is removed on exit (see remove_caches()). The watched files are copied in by
// cache_watched_files()
int create_caches(const char *cache_dir) {
  if (!cache_dir) {
    return -1;
  }

  char path[PATH_MAX];
  const char *leaf;
  const char *reason = NULL;
  int parent_fd = open_trusted_parent("cache directory", cache_dir, 1, path, sizeof(path),
                                      &leaf);
  if (parent_fd < 0) {
    return -1;
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
    return refuse_path("cache directory", cache_dir, NULL, reason);
  }

  // Only a directory this run made, and found empty, is removed on exit
  int owned = created && dir_is_empty(fd);

  // This run's own directory in it, under a name no other run picks
  int run_fd = -1;
  for (int tries = 0; run_fd < 0 && tries < 16; tries++) {
    unsigned char random[8];
    if (getrandom(random, sizeof(random), 0) != (ssize_t)sizeof(random)) {
      reason = strerror(errno);
      break;
    }
    snprintf(run_name, sizeof(run_name), "run.%02x%02x%02x%02x%02x%02x%02x%02x", random[0],
             random[1], random[2], random[3], random[4], random[5], random[6], random[7]);
    if (mkdirat(fd, run_name, 0700) != 0) {
      if (errno != EEXIST) {
        reason = strerror(errno);
        break;
      }
      continue;
    }
    run_fd = openat(fd, run_name, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (run_fd < 0 || fstat(run_fd, &st) != 0) {
      reason = strerror(errno);
    } else if (st.st_uid != geteuid() || (st.st_mode & 077)) {
      reason = "the directory made for this run is not the user's alone";
    }
    if (reason) {
      break;
    }
  }
  if (run_fd < 0 || reason) {
    if (run_fd >= 0) {
      close(run_fd);
    }
    close(fd);
    close(parent_fd);
    return refuse_path("cache directory", cache_dir, NULL, reason ? reason :
                       "no unused name for this run's directory");
  }

  cache_dir_fd = run_fd;
  cache_top_fd = fd;
  cache_parent_fd = parent_fd;
  snprintf(cache_leaf, sizeof(cache_leaf), "%s", leaf);
  cache_dir_owned = owned;
  if (!cache_dir_owned) {
    fprintf(stderr, DARK_GREY "+ Cache directory %s already exists; it will not be removed on exit\n" RESET,
            shown_name(cache_dir));
  }
  return 0;
}

// The log given with -l. A regular file is kept with the descriptor of its
// checked parent and its name, so that it can be opened again there when it
// is rotated or removed; anything else (a terminal, /dev/null, a pipe from
// /dev/stdout or /dev/fd/N, a FIFO) is kept open as it is
FILE *log_stream = NULL;
static const char *log_given;            // the path as given, for messages
static int log_parent_fd = -1;           // regular file only: checked parent
static char log_leaf[NAME_MAX + 1];      // regular file only: name in it
static int log_is_pipe;                  // FIFO or pipe: SIGPIPE held
static int log_broken;                   // the reader of the pipe went away
static sigset_t log_prev_mask;

// Whether fd is the log file. sqwatch does not watch its own log when it is in
// a watched tree: each diff written to it would be a change to diff in turn
int is_log_file(int fd) {
  struct stat log_st, st;
  return log_stream && fstat(fileno(log_stream), &log_st) == 0 && fstat(fd, &st) == 0 &&
         log_st.st_dev == st.st_dev && log_st.st_ino == st.st_ino;
}

static int owned_by_root_or_me(const struct stat *st) {
  return st->st_uid == 0 || st->st_uid == root_uid || st->st_uid == geteuid();
}

// Open leaf beneath parent_fd for appending. A FIFO with no reader yet is
// waited for, as v0.4.1 did, but in steps, so that SIGINT and SIGTERM are
// still answered. Returns a descriptor, or -1 with errno set
static int open_log_at(int parent_fd, const char *leaf, int flags, int is_fifo) {
  int fd = openat(parent_fd, leaf, flags | O_WRONLY | O_APPEND | O_NONBLOCK | O_CLOEXEC, 0600);
  for (int waited = 0; fd < 0 && errno == ENXIO && is_fifo; waited++) {
    if (waited == 0) {
      fprintf(stderr, DARK_GREY "+ Waiting for a reader of the log FIFO %s\n" RESET,
              shown_name(log_given));
    }
    stop_if_signalled();
    usleep(100000);
    fd = openat(parent_fd, leaf, flags | O_WRONLY | O_APPEND | O_NONBLOCK | O_CLOEXEC, 0600);
  }
  return fd;
}

// Why the regular file fd, the log, cannot be used; NULL if it can. It must be
// the user's, have no other name and not be writable by anyone else. It holds
// diffs of the watched files, so a looser mode is made 0600, and said
static const char *regular_log_problem(int fd, const struct stat *st) {
  if (st->st_uid != geteuid()) {
    return "it is owned by another user";
  }
  if (st->st_nlink != 1) {
    return "it has another name (a hard link)";
  }
  if (others_can_write(fd, st)) {
    return "other users can write to it";
  }
  if ((st->st_mode & 07777) != 0600) {
    if (fchmod(fd, 0600) != 0) {
      return strerror(errno);
    }
    fprintf(stderr, DARK_GREY "+ Log file %s had mode %04o; made it 0600, as it holds diffs of watched files\n" RESET,
            shown_name(log_given), (unsigned)(st->st_mode & 07777));
  }
  return NULL;
}

// Open the regular file, FIFO or device leaf beneath its checked parent,
// creating a regular file if there is none. Returns a descriptor, or -1 with
// *why set
static int open_log_leaf(int parent_fd, const char *leaf, const char **why) {
  struct stat st;
  int is_fifo = fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISFIFO(st.st_mode);
  if (is_fifo && !owned_by_root_or_me(&st)) {
    *why = "it is a FIFO owned by another user";
    return -1;
  }
  int fd = open_log_at(parent_fd, leaf, O_CREAT | O_NOFOLLOW, is_fifo);
  if (fd < 0) {
    *why = errno == ELOOP ? "it is a symlink" :
           errno == EISDIR ? "it is a directory" :
           errno == ENXIO ? "it is a socket" : strerror(errno);
    return -1;
  }
  *why = NULL;
  if (fstat(fd, &st) != 0) {
    *why = strerror(errno);
  } else if (S_ISREG(st.st_mode)) {
    *why = regular_log_problem(fd, &st);
  } else if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) {
    // Anyone may make a FIFO in a sticky directory and read the diffs from it
    if (!owned_by_root_or_me(&st)) {
      *why = "it is a FIFO owned by another user";
    }
  } else if (!S_ISCHR(st.st_mode)) {
    *why = S_ISBLK(st.st_mode) ? "it is a block device" : "it is not a file";
  }
  if (*why) {
    close(fd);
    return -1;
  }
  return fd;
}

// Take fd as the log. A regular file is kept with its parent and name
static int use_log_fd(int fd, int parent_fd, const char *leaf) {
  struct stat st;
  FILE *stream = fdopen(fd, "a");
  if (!stream) {
    close(fd);
    return -1;
  }
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
  log_stream = stream;
  log_is_pipe = fstat(fd, &st) == 0 && (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode));
  if (parent_fd >= 0 && S_ISREG(st.st_mode)) {
    log_parent_fd = parent_fd;
    snprintf(log_leaf, sizeof(log_leaf), "%s", leaf);
  } else if (parent_fd >= 0) {
    close(parent_fd);
  }
  return 0;
}

// Open the log file given with -l, once, for the whole run; see log_begin()
// for later writes. Its parent is checked like the cache directory's. A
// symlink there is followed only if root or the user owns it, and its target
// is resolved and checked the same way, from / down. The file opened must be:
//   a regular file: the user's, with no other name, not writable by anyone
//     else (see regular_log_problem()); a missing one is made, mode 0600
//   a terminal or other character device, such as /dev/null: as it is
//   a FIFO: root's or the user's, as anyone can make one in a sticky directory
//   anything reached through /proc/self/fd, as /dev/stdout, /dev/stderr and
//     /dev/fd/N are: a descriptor sqwatch was given, as it is
// Block devices and directories are refused. Returns 0, or -1 once it has
// said why
int open_log_file(const char *log_file) {
  char path[PATH_MAX];
  char next[PATH_MAX];
  const char *leaf;
  const char *why = NULL;
  const char *current = log_file;
  log_given = log_file;

  for (int hops = 0; hops <= 40; hops++) {
    int parent_fd = open_trusted_parent("log file", current, 0, path, sizeof(path), &leaf);
    if (parent_fd < 0) {
      return -1;
    }
    struct stat st;
    if (fstatat(parent_fd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISLNK(st.st_mode)) {
      int fd = open_log_leaf(parent_fd, leaf, &why);
      if (fd >= 0 && use_log_fd(fd, parent_fd, leaf) == 0) {
        return 0;
      }
      close(parent_fd);
      return refuse_path("log file", current, NULL, why ? why : strerror(errno));
    }
    if (!owned_by_root_or_me(&st)) {
      close(parent_fd);
      return refuse_path("log file", current, NULL, "it is a symlink owned by another user");
    }

    struct statfs sfs;
    if (fstatfs(parent_fd, &sfs) == 0 && sfs.f_type == PROC_SUPER_MAGIC) {
      // /proc/self/fd/N: a descriptor of this process; its link is not a path
      struct stat target;
      int is_fifo = fstatat(parent_fd, leaf, &target, 0) == 0 && S_ISFIFO(target.st_mode);
      int fd = open_log_at(parent_fd, leaf, 0, is_fifo);
      if (fd < 0) {
        why = errno == EISDIR ? "it is a directory" : strerror(errno);
      } else if (fstat(fd, &target) != 0) {
        why = strerror(errno);
      } else if (S_ISDIR(target.st_mode) || S_ISBLK(target.st_mode)) {
        why = S_ISDIR(target.st_mode) ? "it is a directory" : "it is a block device";
      }
      if (!why && use_log_fd(fd, -1, NULL) == 0) {
        close(parent_fd);
        return 0;
      }
      if (fd >= 0 && why) {
        close(fd);
      }
      close(parent_fd);
      return refuse_path("log file", current, NULL, why ? why : strerror(errno));
    }

    // Go on from the target, beside the link if it is relative
    char target[PATH_MAX];
    char dir[PATH_MAX];
    char proc_path[32];
    ssize_t n = readlinkat(parent_fd, leaf, target, sizeof(target) - 1);
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", parent_fd);
    ssize_t d = target[0] == '/' ? 0 : readlink(proc_path, dir, sizeof(dir) - 1);
    close(parent_fd);
    if (n < 0 || d < 0) {
      return refuse_path("log file", current, NULL, strerror(errno));
    }
    target[n] = '\0';
    dir[d] = '\0';
    if (snprintf(next, sizeof(next), "%s%s%s", dir, d ? "/" : "", target) >= (int)sizeof(next)) {
      return refuse_path("log file", current, NULL, strerror(ENAMETOOLONG));
    }
    current = next;
  }
  return refuse_path("log file", log_file, NULL, strerror(ELOOP));
}

// The log stream to write an entry to, or NULL if there is none. A regular
// file that was renamed, removed or replaced since it was opened (rotated) is
// opened again beneath its parent with the same checks; if the new one cannot
// be used, logging stops. SIGPIPE is held until log_end() for a pipe, so that
// a reader that went away does not end sqwatch
FILE *log_begin(void) {
  if (!log_stream) {
    return NULL;
  }
  if (log_parent_fd >= 0) {
    struct stat named, opened;
    if (fstatat(log_parent_fd, log_leaf, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
        fstat(fileno(log_stream), &opened) != 0 ||
        named.st_dev != opened.st_dev || named.st_ino != opened.st_ino) {
      const char *why = NULL;
      int fd = open_log_leaf(log_parent_fd, log_leaf, &why);
      struct stat st;
      if (fd >= 0 && (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))) {
        close(fd);
        fd = -1;
        why = "it is not a regular file any more";
      }
      FILE *stream = fd < 0 ? NULL : fdopen(fd, "a");
      fclose(log_stream);
      log_stream = stream;
      if (!stream) {
        if (fd >= 0) {
          close(fd);
        }
        refuse_path("log file", log_given, NULL, why ? why : strerror(errno));
        fprintf(stderr, RED "+ Logging stopped\n" RESET);
        close(log_parent_fd);
        log_parent_fd = -1;
        return NULL;
      }
      fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    }
  }
  if (log_is_pipe) {
    sigset_t pipe_set;
    sigemptyset(&pipe_set);
    sigaddset(&pipe_set, SIGPIPE);
    sigprocmask(SIG_BLOCK, &pipe_set, &log_prev_mask);
  }
  return log_stream;
}

// Finish an entry begun with log_begin()
void log_end(void) {
  if (!log_stream) {
    return;
  }
  int failed = fflush(log_stream) != 0;
  if (log_is_pipe) {
    sigset_t pipe_set;
    struct timespec now = {0, 0};
    sigemptyset(&pipe_set);
    sigaddset(&pipe_set, SIGPIPE);
    while (sigtimedwait(&pipe_set, NULL, &now) > 0) {
    }
    sigprocmask(SIG_SETMASK, &log_prev_mask, NULL);
    if (failed && !log_broken) {
      fprintf(stderr, RED "+ Log %s: %s; entries are lost until it has a reader again\n" RESET,
              shown_name(log_given), strerror(errno));
    }
    log_broken = failed;
    clearerr(log_stream);
  }
}

// Remove what this run put in the cache: its run directory, emptied beneath
// the descriptor it was made with and then removed by name while the name
// still refers to it. The cache directory itself goes too if this run made it
// and nothing else is in it now, again only while its name refers to it.
// Nothing outside the run directory is removed from a directory this run did
// not make
void remove_caches(void) {
  struct stat named, pinned;
  if (cache_dir_fd < 0) {
    return;
  }
  empty_directory(cache_dir_fd);
  if (fstatat(cache_top_fd, run_name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
      fstat(cache_dir_fd, &pinned) == 0 &&
      named.st_dev == pinned.st_dev && named.st_ino == pinned.st_ino) {
    unlinkat(cache_top_fd, run_name, AT_REMOVEDIR);
  }
  if (cache_dir_owned && dir_is_empty(cache_top_fd) &&
      fstatat(cache_parent_fd, cache_leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
      fstat(cache_top_fd, &pinned) == 0 &&
      named.st_dev == pinned.st_dev && named.st_ino == pinned.st_ino) {
    unlinkat(cache_parent_fd, cache_leaf, AT_REMOVEDIR);
  }
}

// A new cache entry: <cache_dir>/<run directory>/<n>, n counting up from 1.
// It is made here, empty and with O_EXCL, in this run's own directory, so it
// is unique among all the files this run watches, no name in a watched tree
// can pick it, and it never holds anything this run did not write. Returns a
// path to free, or NULL
char *cache_new_entry(const char *cache_dir) {
  static unsigned long entries = 0;
  char name[32];
  char *entry = NULL;
  snprintf(name, sizeof(name), "%lu", ++entries);
  int fd = openat(cache_dir_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) {
    return NULL;
  }
  close(fd);
  if (asprintf(&entry, "%s/%s/%s", cache_dir, run_name, name) < 0) {
    unlinkat(cache_dir_fd, name, 0);
    return NULL;
  }
  return entry;
}

// Write the watched file path, read through io_path, into its cache entry
// *cached_path. A file that has an entry already (the watch descriptor is the
// same: another name for the same file) keeps it and it is written again;
// otherwise a new entry is made. If the copy fails the entry is gone (see
// copy_file()) and *cached_path is NULL
void create_cache_for_file(const char *path, const char *io_path, const char *cache_dir,
                          char **cached_path, int verbose) {
    if (!path || !io_path || !cache_dir || !cached_path) {
        return;
    }

    if (!*cached_path) {
        *cached_path = cache_new_entry(cache_dir);
    }
    if (!*cached_path) {
        return;
    }
    if (copy_file(io_path, *cached_path, path) != 0) {
        free(*cached_path);
        *cached_path = NULL;
    } else if (verbose) {
        printf(DARK_GREY "+ Cached: %s\n" RESET, shown_name(path));
    }
}
