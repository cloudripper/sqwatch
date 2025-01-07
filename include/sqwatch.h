#include <sys/types.h>

#ifndef SQWATCH_H
#define SQWATCH_H

#define RED "\033[31m"
#define GREEN "\033[32m"
#define CYAN "\033[36m"
#define DARK_GREY "\033[90m"  // Added dark grey color
#define RESET "\033[0m"

extern pid_t g_last_pid;
int add_watch(int inotify_fd, const char *path, int flags);
void handle_events(int inotify_fd, int wd, const char *command, int flags, uint8_t debounce_t);
void print_usage(void);

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define MAX_PATHS 100

#endif // SQWATCH_H
