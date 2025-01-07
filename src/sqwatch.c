#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#include "sqwatch.h"


pid_t g_last_pid = 0;

static void cleanup(int signo) {
    if (g_last_pid > 0) {
        kill(-g_last_pid, signo);  
        waitpid(g_last_pid, NULL, 0);
    }
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    signal(SIGTERM, cleanup);
    signal(SIGINT, cleanup);

    int inotify_fd;
    int wd = -1;
    char *command = NULL;
    char *paths[MAX_PATHS];
    int path_count = 0;
    int opt;

    inotify_fd = inotify_init();
    if (inotify_fd == -1) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }
    int flags = IN_MODIFY;  

    while ((opt = getopt(argc, argv, "d:f:c:q:h")) != -1) {
        switch (opt) {
            case 'd':
            case 'f':
                if (path_count >= MAX_PATHS) {
                    fprintf(stderr, "Too many paths specified. Maximum is %d\n", MAX_PATHS);
                    exit(EXIT_FAILURE);
                }
                paths[path_count++] = optarg;
                break;
            case 'c':
                command = optarg;
                break;
            case 'q':
                if (strcmp(optarg, "all") == 0) {
                    flags = IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVE | IN_ATTRIB;
                    printf(GREEN "+ Monitoring all events enabled\n" RESET);
                } else if (strcmp(optarg, "modify") == 0) {
                    flags = IN_MODIFY;
                    printf(GREEN "+ Monitoring modify event enabled\n" RESET);
                } else if (strcmp(optarg, "create") == 0) {
                    flags = IN_CREATE;
                    printf(GREEN "+ Monitoring create event enabled\n" RESET);
                } else if (strcmp(optarg, "delete") == 0) {
                    flags = IN_DELETE;
                    printf(GREEN "+ Monitoring delete event enabled\n" RESET);
                } else if (strcmp(optarg, "move") == 0) {
                    flags = IN_MOVE;
                    printf(GREEN "+ Monitoring move event enabled\n" RESET);
                } else if (strcmp(optarg, "attrib") == 0) {
                    flags = IN_ATTRIB;
                    printf(GREEN "+ Monitoring attribute events enabled\n" RESET);
                } else {
                    fprintf(stderr, "Invalid query option: %s\n", optarg);
                    print_usage();
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
            
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (command == NULL || path_count == 0) {
        fprintf(stderr, "Both paths and command are required\n");
        print_usage();
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < path_count; i++) {
        wd = add_watch(inotify_fd, paths[i], flags);
        if (wd == -1) {
            fprintf(stderr, RED "+ Failed to add watch for %s\n" RESET, paths[i]);
            continue;
        }
        printf(CYAN "+ Watch set for %s\n" RESET, paths[i]);
    }

    handle_events(inotify_fd, wd, command, flags);

    close(inotify_fd);
    cleanup(SIGTERM); 

    return EXIT_SUCCESS;
}

