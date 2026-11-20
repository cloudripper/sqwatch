#ifndef PERMISSION_H
#define PERMISSION_H

#include <stdint.h>
#include <sys/types.h>

// -p: opens, reads or execs of the watched files wait for the command to
// allow or deny them (fanotify permission events)

// Path of the watched regular file dev/ino, as sqwatch shows it, or NULL if
// it is not watched
typedef const char *(*perm_lookup)(dev_t dev, ino_t ino);

void perm_start(uint64_t mask, long long timeout_ms, int deny_on_timeout, const char *command,
                perm_lookup lookup);
int perm_active(void);
void perm_mark(const char *io_path, int is_dir);
int perm_wake_fd(void);
int perm_decider_fd(void);
int perm_work(void);
void perm_shutdown(void);

#endif // PERMISSION_H
