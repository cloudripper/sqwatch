#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sqwatch.h"

extern pid_t g_last_pid;
extern char **environ;

const char* get_signal_desc(int signo) {
    switch (signo) {
        case SIGFPE:  return "SIGFPE:  Floating point exception";
        case SIGILL:  return "SIGILL:  Illegal instruction";
        case SIGSEGV: return "SIGSEGV: Segmentation fault";
        case SIGBUS:  return "SIGBUS:  Bus error";
        case SIGABRT: return "SIGABRT: Aborted";
        case SIGTERM: return "SIGTERM: Terminated";
        case SIGINT:  return "SIGINT:  Interrupted";
        default:      return "Unknown signal";
    }
}

int add_watch(int inotify_fd, const char *path, int flags) {
  int wd = inotify_add_watch(inotify_fd, path, flags);
  return wd;
}

void print_event_type(struct inotify_event *event) {
  // Print without newline
  switch (event->mask) {
  case IN_MODIFY:
    printf(CYAN "Modified " RESET);
    break;
  case IN_CREATE:
    printf(CYAN "Created " RESET);
    break;
  case IN_DELETE:
    printf(CYAN "Deleted " RESET);
    break;
  case IN_MOVED_FROM:
    printf(CYAN "Moved from " RESET);
    break;
  case IN_MOVED_TO:
    printf(CYAN "Moved to " RESET);
    break;
  case IN_ATTRIB:
    printf(CYAN "Attributes " RESET);
    break;
  }
  fflush(stdout);  // Ensure partial line is displayed
}

void handle_events(int inotify_fd, int wd, const char *command, int flags, uint8_t debounce_t) {
  char buffer[BUF_LEN];
  int length;
  time_t last_event = 0;
  int events_since_last_run = 0;
  char event_buffer[256] = "";  // Buffer to store event descriptions

  while (1) {
    length = read(inotify_fd, buffer, BUF_LEN);
    if (length < 0) {
      perror("read");
      exit(EXIT_FAILURE);
    }

    int i = 0;
    while (i < length) {
      struct inotify_event *event = (struct inotify_event *)&buffer[i];
      
      time_t now = time(NULL);
      if (now - last_event >= debounce_t) {
        if (events_since_last_run > 0) {
          printf(DARK_GREY "+ Debounced: [ %s ]\n" RESET, event_buffer);  // Print debounced events
          event_buffer[0] = '\0';  // Clear the buffer
        }
        events_since_last_run = 0;
      }
      
      if (event->wd == wd && event->mask & (flags)) {
        char event_desc[32];
        snprintf(event_desc, sizeof(event_desc), "%s", event->mask & IN_MODIFY ? "Modified" :
                                                      event->mask & IN_CREATE ? "Created" :
                                                      event->mask & IN_DELETE ? "Deleted" :
                                                      event->mask & IN_MOVED_FROM ? "Moved from" :
                                                      event->mask & IN_MOVED_TO ? "Moved to" :
                                                      event->mask & IN_ATTRIB ? "Attributes" : "Unknown");

        if (now - last_event >= debounce_t) {
          if (g_last_pid > 0) {
            kill(-g_last_pid, SIGTERM);
            waitpid(g_last_pid, NULL, 0);
          }

          printf(CYAN "+ Trigger: [ %s ]\n" RESET, event_desc);  // Print the trigger event

          g_last_pid = fork();
          if (g_last_pid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
          }

          if (g_last_pid == 0) {
            setpgid(0, 0);
            setvbuf(stdout, NULL, _IONBF, 0);
            setvbuf(stderr, NULL, _IONBF, 0);
            char *const args[] = {"/bin/sh", "-c", (char *)command, NULL};
            execve("/bin/sh", args, environ);
            perror("execve");
            exit(EXIT_FAILURE);
          }

          int status;
          waitpid(g_last_pid, &status, 0);
          if (WIFSIGNALED(status)) {
            int sig = WTERMSIG(status);
            fprintf(stderr, RED "+ Command terminated by signal %d (%s)\n" RESET, 
                    sig, get_signal_desc(sig));
          }
          
          last_event = now;
        } else {
          if (event_buffer[0] != '\0') {
            strncat(event_buffer, ", ", sizeof(event_buffer) - strlen(event_buffer) - 1);
          }
          strncat(event_buffer, event_desc, sizeof(event_buffer) - strlen(event_buffer) - 1);
        }
        events_since_last_run++;
      }
      i += EVENT_SIZE + event->len;
    }
  }
}

void print_usage(void) {
  printf("Usage: sqwatch [-d directory] [-f file] [-t debounce time] -q event -c command\n");
  printf("Options:\n");
  printf("  -d directory      Directory to watch\n");
  printf("  -f file           File to watch\n");
  printf("  -t debounce time  Time (in seconds) after trigger to ignore events\n");
  printf("  -q event          Event type to watch\n");
  printf("                     all: all events\n");
  printf("                     modify: file modifications\n");
  printf("                     create: file creation\n");
  printf("                     delete: file deletion\n");
  printf("                     move: file moves\n");
  printf("                     attrib: attribute changes\n");
  printf("  -c command        Command to execute when events are detected\n");
  printf("  -h                Display this help message\n");
}
