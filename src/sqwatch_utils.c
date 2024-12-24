#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>

#include "sqwatch.h"

extern pid_t g_last_pid;

int add_watch(int inotify_fd, const char *path, int flags) {
    int wd = inotify_add_watch(inotify_fd, path, flags);
    return wd;
}

void handle_events(int inotify_fd, int wd, const char *command, int flags) {
    char buffer[BUF_LEN];
    int length;
    time_t last_event = 0;

    while (1) {
        length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            if (event->wd == wd && event->mask & (flags)) {
                time_t now = time(NULL);
                if (now - last_event >= 1) {
                    if (g_last_pid > 0) {
                        kill(-g_last_pid, SIGTERM);
                        waitpid(g_last_pid, NULL, 0);
                    }

                    g_last_pid = fork();
                    if (g_last_pid == -1) {
                        perror("fork");
                        exit(EXIT_FAILURE);
                    }
                    
                    if (g_last_pid == 0) {  
                        setpgid(0, 0);
                        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
                        perror("execl");
                        exit(EXIT_FAILURE);
                    }
                    
                    last_event = now;
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }
}

void print_usage(void) {
    printf("Usage: sqwatch [-d directory] [-f file] -q event -c command\n");
    printf("Options:\n");
    printf("  -d directory  Directory to watch\n");
    printf("  -f file       File to watch\n");
    printf("  -q event      Event type to watch\n");
    printf("                 all: all events\n");
    printf("                 modify: file modifications\n");
    printf("                 create: file creation\n");
    printf("                 delete: file deletion\n");
    printf("                 move: file moves\n");
    printf("                 attrib: attribute changes\n");
    printf("  -c command    Command to execute when events are detected\n");
    printf("  -h            Display this help message\n");
}
