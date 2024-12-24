#include <sys/types.h>

#ifndef SQWATCH_H
#define SQWATCH_H

extern pid_t g_last_pid; 
int add_watch(int inotify_fd, const char *path, int flags);
void handle_events(int inotify_fd, int wd, const char *command, int flags);
void print_usage(void);

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define MAX_PATHS 100

#endif // SQWATCH_H