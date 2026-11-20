#define _GNU_SOURCE
#include "permission.h"
#include "sqwatch.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// How it works. A reader thread takes the permission events from fanotify as
// they come and answers at once those that must not wait: sqwatch's own opens
// (its copies and diffs, which it makes while the main thread may be the one
// that would have to answer), and those of the command deciding an event and
// of its process group. The others are queued for the main thread, which runs
// the command for one at a time, and answers from its exit status. The queue
// is bounded: an event that does not fit is allowed. Whatever goes wrong, the
// event is allowed; on exit every event left is allowed, and closing the
// fanotify descriptor makes the kernel allow anything still on its way

#define QUEUE_SIZE 256
#define PERM_EVENTS (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM)

typedef struct {
    int fd;                  // The file opened, from fanotify; to answer and close
    pid_t pid;               // The process that opened it
    uint64_t mask;
} perm_event;

static int fan_fd = -1;
static uint64_t perm_mask;
static long long timeout_ms;
static int deny_on_timeout;
static const char *decider_command;
static perm_lookup lookup;

// Shared between the reader thread and the main thread
static int stop_pipe[2] = {-1, -1};
static int wake_pipe[2] = {-1, -1};
static pthread_t reader;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static perm_event queue[QUEUE_SIZE];
static size_t queue_head, queue_count;
static pid_t decider_pgid;           // Read and written with __atomic
static unsigned long overloaded;     // Events allowed as the queue was full

// The main thread's: the command deciding an event, if one is running
static pid_t decider;
static int decider_pidfd = -1;
static perm_event current;
static char current_path[4 * 4096 + 1];
static long long deadline;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Answer a permission event, and close its descriptor
static void respond(int fd, int allow) {
    struct fanotify_response response = {fd, allow ? FAN_ALLOW : FAN_DENY};
    if (write(fan_fd, &response, sizeof(response)) != (ssize_t)sizeof(response)) {
        // Nothing more can be done: the kernel allows it once fan_fd closes
    }
    close(fd);
}

static void *read_events(void *unused) {
    (void)unused;
    union {
        struct fanotify_event_metadata metadata;
        char bytes[8192];
    } buffer;
    pid_t self = getpid();
    while (1) {
        struct pollfd fds[2] = {{fan_fd, POLLIN, 0}, {stop_pipe[0], POLLIN, 0}};
        if (poll(fds, 2, -1) < 0) {
            continue;
        }
        if (fds[1].revents) {
            return NULL;
        }
        ssize_t len = read(fan_fd, buffer.bytes, sizeof(buffer.bytes));
        if (len <= 0) {
            continue;
        }
        int queued = 0;
        struct fanotify_event_metadata *event = &buffer.metadata;
        for (; FAN_EVENT_OK(event, len); event = FAN_EVENT_NEXT(event, len)) {
            if (event->fd < 0) {
                continue;  // A queue overflow: nothing waits for an answer
            }
            if (event->vers != FANOTIFY_METADATA_VERSION || !(event->mask & PERM_EVENTS)) {
                respond(event->fd, 1);
                continue;
            }
            pid_t group = __atomic_load_n(&decider_pgid, __ATOMIC_SEQ_CST);
            if (event->pid == self || (group > 0 && getpgid(event->pid) == group)) {
                respond(event->fd, 1);
                continue;
            }
            pthread_mutex_lock(&queue_lock);
            if (queue_count == QUEUE_SIZE) {
                pthread_mutex_unlock(&queue_lock);
                respond(event->fd, 1);
                __atomic_add_fetch(&overloaded, 1, __ATOMIC_SEQ_CST);
            } else {
                queue[(queue_head + queue_count++) % QUEUE_SIZE] =
                    (perm_event){event->fd, event->pid, event->mask};
                pthread_mutex_unlock(&queue_lock);
            }
            queued = 1;
        }
        if (queued && write(wake_pipe[1], "x", 1) < 0) {
            // The pipe is full: the main thread is woken already
        }
    }
}

// Start listening for mask on the marks perm_mark() sets. command decides each
// event, within timeout_ms; then the event is allowed, or denied if
// deny_on_timeout. Exits if fanotify permission events cannot be used
void perm_start(uint64_t mask, long long timeout, int deny, const char *command,
                perm_lookup find) {
    fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                           O_RDONLY | O_LARGEFILE | O_CLOEXEC);
    if (fan_fd < 0) {
        if (errno == EPERM) {
            fprintf(stderr, "sqwatch: -p needs the CAP_SYS_ADMIN capability: run sqwatch as root\n");
        } else {
            fprintf(stderr, "sqwatch: -p: fanotify permission events cannot be used here: %s\n",
                    strerror(errno));
        }
        exit(EXIT_FAILURE);
    }
    perm_mask = mask;
    timeout_ms = timeout;
    deny_on_timeout = deny;
    decider_command = command;
    lookup = find;
    if (pipe2(stop_pipe, O_CLOEXEC) != 0 || pipe2(wake_pipe, O_CLOEXEC | O_NONBLOCK) != 0 ||
        pthread_create(&reader, NULL, read_events, NULL) != 0) {
        perror("sqwatch: -p");
        exit(EXIT_FAILURE);
    }
}

int perm_active(void) {
    return fan_fd >= 0;
}

// Mark the file or directory io_path names; a directory's mark covers the
// files in it. Only the inode is marked, never its mount or filesystem
void perm_mark(const char *io_path, int is_dir) {
    static int warned;
    if (fan_fd < 0) {
        return;
    }
    if (fanotify_mark(fan_fd, FAN_MARK_ADD, perm_mask | (is_dir ? FAN_EVENT_ON_CHILD : 0),
                      AT_FDCWD, io_path) != 0 && !warned) {
        fprintf(stderr, RED "+ -p: cannot mark everything watched: %s\n" RESET, strerror(errno));
        warned = 1;
    }
}

int perm_wake_fd(void) {
    return wake_pipe[0];
}

int perm_decider_fd(void) {
    return decider ? decider_pidfd : -1;
}

static const char *event_of(uint64_t mask) {
    return mask & FAN_OPEN_EXEC_PERM ? "exec" : mask & FAN_ACCESS_PERM ? "access" : "open";
}

// The deciding command is done: answer its event
static void decided(int allow, const char *why) {
    printf(CYAN "+ %s of %s by pid %d: %s%s\n" RESET, event_of(current.mask),
           shown_name(current_path), (int)current.pid, allow ? "allowed" : "denied", why);
    respond(current.fd, allow);
    // What the command left behind in its group goes too
    killpg(decider, SIGKILL);
    while (waitpid(-decider, NULL, WNOHANG) > 0) {
    }
    __atomic_store_n(&decider_pgid, 0, __ATOMIC_SEQ_CST);
    if (decider_pidfd >= 0) {
        close(decider_pidfd);
        decider_pidfd = -1;
    }
    decider = 0;
}

// Run the command for the event current, path, with the event in its
// environment. It starts only once its process group is known to the reader
// thread, so its own opens are never held
static int start_decider(void) {
    int go[2];
    char pid_text[16];
    if (pipe2(go, O_CLOEXEC) != 0) {
        return -1;
    }
    snprintf(pid_text, sizeof(pid_text), "%d", (int)current.pid);
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        close(go[0]);
        close(go[1]);
        return -1;
    }
    if (pid == 0) {
        sigset_t all;
        char ready;
        sigemptyset(&all);
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        sigprocmask(SIG_SETMASK, &all, NULL);
        setpgid(0, 0);
        setenv("SQWATCH_PATH", current_path, 1);
        setenv("SQWATCH_EVENT", event_of(current.mask), 1);
        setenv("SQWATCH_PID", pid_text, 1);
        close(go[1]);
        if (read(go[0], &ready, 1) != 1) {
            _exit(EXIT_FAILURE);
        }
        execl("/bin/sh", "sh", "-c", decider_command, (char *)NULL);
        _exit(127);
    }
    setpgid(pid, pid);
    __atomic_store_n(&decider_pgid, pid, __ATOMIC_SEQ_CST);
    if (write(go[1], "x", 1) != 1) {
        // The child exits on its own if it never gets the byte
    }
    close(go[0]);
    close(go[1]);
    decider = pid;
    decider_pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    deadline = now_ms() + timeout_ms;
    return 0;
}

// Take the events the reader thread queued and decide them, one command at a
// time. Returns the ms until a deadline, or -1 if there is none
int perm_work(void) {
    char drain[64];
    while (read(wake_pipe[0], drain, sizeof(drain)) > 0) {
    }
    // Accesses allowed for want of room are told at most once a second
    static long long told;
    if (__atomic_load_n(&overloaded, __ATOMIC_SEQ_CST) && now_ms() - told >= 1000) {
        unsigned long dropped = __atomic_exchange_n(&overloaded, 0, __ATOMIC_SEQ_CST);
        fprintf(stderr, RED "+ -p: too many events waiting: %lu allowed without asking\n" RESET,
                dropped);
        told = now_ms();
    }
    if (decider) {
        int status;
        if (waitpid(decider, &status, WNOHANG) == decider) {
            char why[48] = "";
            int allow = WIFEXITED(status) && WEXITSTATUS(status) == 0;
            if (WIFEXITED(status) && !allow) {
                snprintf(why, sizeof(why), " (exit status %d)", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                snprintf(why, sizeof(why), " (killed by signal %d)", WTERMSIG(status));
            }
            decided(allow, why);
        } else if (now_ms() >= deadline) {
            killpg(decider, SIGKILL);
            waitpid(decider, NULL, 0);
            decided(!deny_on_timeout, " (the command timed out)");
        }
    }
    while (!decider) {
        pthread_mutex_lock(&queue_lock);
        if (queue_count == 0) {
            pthread_mutex_unlock(&queue_lock);
            break;
        }
        current = queue[queue_head];
        queue_head = (queue_head + 1) % QUEUE_SIZE;
        queue_count--;
        pthread_mutex_unlock(&queue_lock);

        // Only a regular file sqwatch watches is decided: an ignored file in
        // a marked directory, or one not seen yet, is allowed
        struct stat st;
        const char *path = fstat(current.fd, &st) == 0 && S_ISREG(st.st_mode) ?
            lookup(st.st_dev, st.st_ino) : NULL;
        if (!path) {
            respond(current.fd, 1);
            continue;
        }
        snprintf(current_path, sizeof(current_path), "%s", path);
        if (start_decider() != 0) {
            fprintf(stderr, RED "+ -p: could not start the command (%s): %s of %s allowed\n" RESET,
                    strerror(errno), event_of(current.mask), shown_name(current_path));
            respond(current.fd, 1);
        }
    }
    if (!decider) {
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
        return -1;
    }
    long long left = deadline - now_ms();
    if (left < 0) {
        left = 0;
    }
    // Without a pidfd the end of the command is looked for every 10 ms
    return decider_pidfd < 0 && left > 10 ? 10 : (int)left;
}

// Allow every event waiting, stop the command deciding one, stop the reader
// thread and close fanotify, which allows whatever is still on its way
void perm_shutdown(void) {
    if (fan_fd < 0) {
        return;
    }
    if (write(stop_pipe[1], "x", 1) == 1) {
        pthread_join(reader, NULL);
    }
    if (decider) {
        killpg(decider, SIGKILL);
        waitpid(decider, NULL, 0);
        decided(1, " (sqwatch is exiting)");
    }
    pthread_mutex_lock(&queue_lock);
    while (queue_count > 0) {
        respond(queue[queue_head].fd, 1);
        queue_head = (queue_head + 1) % QUEUE_SIZE;
        queue_count--;
    }
    pthread_mutex_unlock(&queue_lock);
    close(fan_fd);
    fan_fd = -1;
}
