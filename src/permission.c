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

// How it works. -p is a gate, and it fails closed: whatever cannot be decided
// by the command in time is denied, unless -T says allow (fail_allow).
//
// A reader thread takes the permission events from fanotify as they come. It
// answers at once those that must not wait: sqwatch's own opens (its copies
// and diffs, which it makes while the main thread may be the one that would
// have to answer), and those of the command deciding an event (its session,
// see start_decider()). It queues the others for the main thread, which runs
// the command for one at a time, and answers from its exit status. Each event
// has a deadline, its arrival plus the timeout: the reader thread answers
// every event past its deadline by the policy, queued or being decided,
// whatever the main thread is doing (printing to a stalled terminal, say).
// An event that does not fit in the queue, or past the quota of its user,
// is answered by the policy at once. Every answer is made once, under
// queue_lock. The main thread prints; the reader thread never does.
//
// What fanotify cannot cover: when sqwatch dies (SIGKILL, a crash, the OOM
// killer), the kernel removes its marks and allows everything

#define QUEUE_SIZE 256
#define UID_QUOTA 64             // Events one user may have queued
#define PERM_EVENTS (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM)

typedef struct {
    int fd;                  // The file opened, from fanotify; -1 once answered
    pid_t pid;               // The process that opened it
    uid_t uid;               // Its owner, as /proc shows it
    uint64_t mask;
    long long arrived;       // ms of CLOCK_MONOTONIC
    int allowed;             // Once answered: how
    const char *why;         // Once answered by the reader thread: why
} perm_event;

static int fan_fd = -1;
static uint64_t perm_mask;
static long long timeout_ms;
static int fail_allow;       // -T ...:allow: allow what is not decided
static const char *decider_command;
static perm_lookup lookup;
static int started;          // The startup walk is done (see perm_ready())

// Shared between the reader thread and the main thread, under queue_lock
static int stop_pipe[2] = {-1, -1};
static int wake_pipe[2] = {-1, -1};
static pthread_t reader;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static perm_event queue[QUEUE_SIZE];
static size_t queue_head, queue_count;
static perm_event current;   // The event being decided, if current_active
static int current_active;
static pid_t decider_sid;    // The decider's session (and group); 0 if none
static unsigned long refused;   // Events answered by the policy: no room
static unsigned long expired;   // Events answered by the policy: no answer in time

// The main thread's: the command deciding current
static pid_t decider;
static int decider_pidfd = -1;
static char current_path[4 * 4096 + 1];

// Directories that could not be marked after startup: an event sqwatch
// cannot name beneath one of them is denied
static char **unmarked;
static size_t unmarked_count;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Answer the event e, unless it was answered already, and close its
// descriptor. Called with queue_lock held
static void answer(perm_event *e, int allow, const char *why) {
    if (e->fd < 0) {
        return;
    }
    struct fanotify_response response = {e->fd, allow ? FAN_ALLOW : FAN_DENY};
    if (write(fan_fd, &response, sizeof(response)) != (ssize_t)sizeof(response)) {
        // Nothing more can be done: the kernel allows it once fan_fd closes
    }
    close(e->fd);
    e->fd = -1;
    e->allowed = allow;
    e->why = why;
}

// Answer the fanotify event fd at once
static void answer_fd(int fd, int allow) {
    perm_event e = {fd, 0, 0, 0, 0, 0, NULL};
    answer(&e, allow, NULL);
}

// Whether pid is the deciding command or one of its processes: in its
// session and its process group. The session cannot be joined from outside,
// and its id is not given to another process while the command, or anything
// left of its group, is there (see perm_work())
static int is_decider(pid_t pid) {
    pid_t sid = __atomic_load_n(&decider_sid, __ATOMIC_SEQ_CST);
    return sid > 0 && getsid(pid) == sid && getpgid(pid) == sid;
}

static uid_t uid_of(pid_t pid) {
    char proc[32];
    struct stat st;
    snprintf(proc, sizeof(proc), "/proc/%d", (int)pid);
    return stat(proc, &st) == 0 ? st.st_uid : (uid_t)-1;
}

// The ms until the earliest deadline of the events waiting, or -1; answers
// those past it. Called with queue_lock held
static int expire(void) {
    long long now = now_ms(), next = -1;
    for (size_t i = 0; i <= queue_count; i++) {
        perm_event *e = i < queue_count ? &queue[(queue_head + i) % QUEUE_SIZE] :
                        current_active ? &current : NULL;
        if (!e || e->fd < 0) {
            continue;
        }
        long long left = e->arrived + timeout_ms - now;
        if (left <= 0) {
            answer(e, fail_allow, "no decision in time");
            expired++;
        } else if (next < 0 || left < next) {
            next = left;
        }
    }
    return next < 0 ? -1 : next > 60000 ? 60000 : (int)next;
}

static void wake_main(void) {
    if (write(wake_pipe[1], "x", 1) < 0) {
        // The pipe is full: the main thread is woken already
    }
}

static void *read_events(void *unused) {
    (void)unused;
    union {
        struct fanotify_event_metadata metadata;
        char bytes[8192];
    } buffer;
    pid_t self = getpid();
    while (1) {
        pthread_mutex_lock(&queue_lock);
        unsigned long expired_before = expired;
        int timeout = expire();
        int woke = expired != expired_before;
        pthread_mutex_unlock(&queue_lock);
        if (woke) {
            wake_main();
        }
        struct pollfd fds[2] = {{fan_fd, POLLIN, 0}, {stop_pipe[0], POLLIN, 0}};
        if (poll(fds, 2, timeout) < 0) {
            continue;
        }
        if (fds[1].revents) {
            return NULL;
        }
        if (!(fds[0].revents & POLLIN)) {
            continue;
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
                answer_fd(event->fd, 1);
                continue;
            }
            if (event->pid == self || is_decider(event->pid)) {
                answer_fd(event->fd, 1);
                continue;
            }
            uid_t uid = uid_of(event->pid);
            pthread_mutex_lock(&queue_lock);
            size_t mine = 0;
            for (size_t i = 0; i < queue_count; i++) {
                mine += queue[(queue_head + i) % QUEUE_SIZE].uid == uid;
            }
            if (queue_count == QUEUE_SIZE || mine >= UID_QUOTA) {
                perm_event e = {event->fd, event->pid, uid, event->mask, 0, 0, NULL};
                answer(&e, fail_allow, NULL);
                refused++;
            } else {
                queue[(queue_head + queue_count++) % QUEUE_SIZE] =
                    (perm_event){event->fd, event->pid, uid, event->mask, now_ms(), 0, NULL};
            }
            pthread_mutex_unlock(&queue_lock);
            queued = 1;
        }
        if (queued) {
            wake_main();
        }
    }
}

// Start listening for mask on the marks perm_mark() sets. command decides each
// event, within timeout_ms; what is not decided then, or cannot be decided,
// is denied, or allowed if allow. Exits if fanotify permission events cannot
// be used
void perm_start(uint64_t mask, long long timeout, int allow, const char *command,
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
    fail_allow = allow;
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

// The startup walk is done: from now on a directory that cannot be marked is
// reported, not fatal
void perm_ready(void) {
    started = 1;
}

// Mark the file or directory io_path names, shown as shown; a directory's
// mark covers the files in it, a file's own mark stays with it wherever it is
// moved. Only the inode is marked, never its mount or filesystem. A directory
// that cannot be marked ends sqwatch at startup: what is in it would not be
// gated. Later it is reported, and an event sqwatch cannot name beneath it is
// denied. A file that cannot be marked (the limit of marks is reached) is
// still gated through its directory while it is in the tree
void perm_mark(const char *io_path, int is_dir, const char *shown) {
    static int file_warned;
    if (fan_fd < 0) {
        return;
    }
    if (fanotify_mark(fan_fd, FAN_MARK_ADD, perm_mask | (is_dir ? FAN_EVENT_ON_CHILD : 0),
                      AT_FDCWD, io_path) == 0) {
        return;
    }
    if (!is_dir) {
        if (!file_warned) {
            fprintf(stderr, RED "+ -p: cannot mark %s on its own (%s): from here on, files are gated only while they are in a watched directory\n" RESET,
                    shown_name(shown), strerror(errno));
            file_warned = 1;
        }
        return;
    }
    if (!started) {
        fprintf(stderr, "sqwatch: -p: cannot mark the directory %s: %s; cannot guarantee coverage\n",
                shown_name(shown), strerror(errno));
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, RED "+ -p: CANNOT MARK THE DIRECTORY %s (%s): ITS FILES ARE NOT GATED\n" RESET,
            shown_name(shown), strerror(errno));
    char **grown = realloc(unmarked, (unmarked_count + 1) * sizeof(*grown));
    char *copy = strdup(shown);
    if (grown && copy) {
        unmarked = grown;
        unmarked[unmarked_count++] = copy;
    } else {
        free(copy);
        if (grown) {
            unmarked = grown;
        }
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

static void tell(const perm_event *e, const char *path, int allowed, const char *why) {
    printf(CYAN "+ %s of %s by pid %d: %s%s%s%s\n" RESET, event_of(e->mask), shown_name(path),
           (int)e->pid, allowed ? "allowed" : "denied", why ? " (" : "", why ? why : "",
           why ? ")" : "");
}

// The decider has ended (it is a zombie, not reaped: its pid and group id are
// still its own), or must: kill what is left of its group, stop trusting its
// session, answer its event if the reader thread has not, and only then reap
// it. Every wait is bounded
static void end_decider(int allow, const char *why) {
    killpg(decider, SIGKILL);
    pthread_mutex_lock(&queue_lock);
    __atomic_store_n(&decider_sid, 0, __ATOMIC_SEQ_CST);
    answer(&current, allow, why);
    perm_event done = current;
    current_active = 0;
    pthread_mutex_unlock(&queue_lock);
    tell(&done, current_path, done.allowed, done.why);

    // Reap it: it is dead or dies from the KILL; a process stuck in the
    // kernel is left for later, as a zombie the next calls reap
    struct pollfd p = {decider_pidfd, POLLIN, 0};
    if (decider_pidfd >= 0) {
        poll(&p, 1, 1000);
    }
    waitpid(decider, NULL, WNOHANG);
    while (waitpid(-decider, NULL, WNOHANG) > 0) {
    }
    if (decider_pidfd >= 0) {
        close(decider_pidfd);
        decider_pidfd = -1;
    }
    decider = 0;
}

// The environment of the decider: sqwatch's, with the SQWATCH_ variables set
// (made before fork(): the child of a threaded process may not allocate).
// Returns a NULL-terminated array, whose strings from *own on are to free,
// or NULL
static char **decider_env(size_t *own) {
    size_t n = 0;
    while (environ[n]) {
        n++;
    }
    char **env = calloc(n + 5, sizeof(*env));
    if (!env) {
        return NULL;
    }
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (strncmp(environ[i], "SQWATCH_PATH=", 13) != 0 &&
            strncmp(environ[i], "SQWATCH_EVENT=", 14) != 0 &&
            strncmp(environ[i], "SQWATCH_PID=", 12) != 0 &&
            strncmp(environ[i], "SQWATCH_FD=", 11) != 0) {
            env[k++] = environ[i];
        }
    }
    *own = k;
    if (asprintf(&env[k], "SQWATCH_PATH=%s", current_path) < 0 ||
        asprintf(&env[k + 1], "SQWATCH_EVENT=%s", event_of(current.mask)) < 0 ||
        asprintf(&env[k + 2], "SQWATCH_PID=%d", (int)current.pid) < 0 ||
        asprintf(&env[k + 3], "SQWATCH_FD=3") < 0) {
        for (size_t i = k; i < k + 4; i++) {
            free(env[i]);  // NULL, or the strings made
            env[i] = NULL;
        }
        free(env);
        return NULL;
    }
    return env;
}

static void free_env(char **env, size_t own) {
    for (size_t i = own; env[i]; i++) {
        free(env[i]);
    }
    free(env);
}

// Run the command for the event current, with the event in its environment,
// and the file being opened as its descriptor 3. It runs in a session of its
// own, which no other process can join, and starts only once sqwatch trusts
// that session, so its own opens are never held
static int start_decider(void) {
    int go[2];
    size_t own;
    char **env = decider_env(&own);
    if (!env) {
        return -1;
    }
    if (pipe2(go, O_CLOEXEC) != 0) {
        free_env(env, own);
        return -1;
    }
    fflush(stdout);
    fflush(stderr);
    // The reader thread may not answer the event, and close its descriptor,
    // while the child takes it
    pthread_mutex_lock(&queue_lock);
    pid_t pid = current.fd >= 0 ? fork() : (errno = ETIMEDOUT, -1);
    pthread_mutex_unlock(&queue_lock);
    if (pid < 0) {
        close(go[0]);
        close(go[1]);
        free_env(env, own);
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
        setsid();
        int fd = current.fd;
        if (fd == 3 ? fcntl(3, F_SETFD, 0) != 0 : dup2(fd, 3) != 3) {
            _exit(EXIT_FAILURE);
        }
        close(go[1]);
        if (read(go[0], &ready, 1) != 1) {
            _exit(EXIT_FAILURE);
        }
        char *const args[] = {"sh", "-c", (char *)decider_command, NULL};
        execve("/bin/sh", args, env);
        _exit(127);
    }
    free_env(env, own);
    __atomic_store_n(&decider_sid, pid, __ATOMIC_SEQ_CST);
    if (write(go[1], "x", 1) != 1) {
        // The child exits on its own if it never gets the byte
    }
    close(go[0]);
    close(go[1]);
    decider = pid;
    decider_pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    return 0;
}

// Whether path is beneath a directory that could not be marked
static int in_unmarked(const char *path) {
    for (size_t i = 0; i < unmarked_count; i++) {
        size_t len = strlen(unmarked[i]);
        if (strncmp(path, unmarked[i], len) == 0 && path[len] == '/') {
            return 1;
        }
    }
    return 0;
}

// Take the events the reader thread queued and decide them, one command at a
// time. Returns the ms until the decider's deadline, or -1 if there is none
int perm_work(void) {
    char drain[64];
    while (read(wake_pipe[0], drain, sizeof(drain)) > 0) {
    }
    // What the policy answered for want of room or time is told at most
    // once a second
    static long long told;
    if (now_ms() - told >= 1000) {
        pthread_mutex_lock(&queue_lock);
        unsigned long no_room = refused;
        refused = 0;
        pthread_mutex_unlock(&queue_lock);
        if (no_room) {
            fprintf(stderr, RED "+ -p: too many events waiting: %lu %s without asking\n" RESET,
                    no_room, fail_allow ? "allowed" : "denied");
            told = now_ms();
        }
    }
    if (decider) {
        siginfo_t info = {0};
        int done = waitid(P_PID, (id_t)decider, &info, WEXITED | WNOHANG | WNOWAIT) == 0 &&
                   info.si_pid == decider;
        pthread_mutex_lock(&queue_lock);
        int answered = current.fd < 0;
        long long left = current.arrived + timeout_ms - now_ms();
        pthread_mutex_unlock(&queue_lock);
        if (done) {
            static char why[48];
            int allow = info.si_code == CLD_EXITED && info.si_status == 0;
            if (info.si_code == CLD_EXITED) {
                snprintf(why, sizeof(why), "exit status %d", info.si_status);
            } else {
                snprintf(why, sizeof(why), "killed by signal %d", info.si_status);
            }
            end_decider(allow, allow ? NULL : why);
        } else if (answered || left <= 0) {
            end_decider(fail_allow, "no decision in time");
        }
    }
    while (!decider) {
        pthread_mutex_lock(&queue_lock);
        if (queue_count == 0) {
            pthread_mutex_unlock(&queue_lock);
            break;
        }
        perm_event next = queue[queue_head];
        queue_head = (queue_head + 1) % QUEUE_SIZE;
        queue_count--;
        if (next.fd >= 0) {
            current = next;
            current_active = 1;
        }
        pthread_mutex_unlock(&queue_lock);

        // The path the command gets is for information: the watched name of
        // the file, or what its descriptor's link in /proc says. The file
        // itself is its descriptor 3
        struct stat st;
        const char *path = next.fd >= 0 && fstat(next.fd, &st) == 0 && S_ISREG(st.st_mode) ?
            lookup(st.st_dev, st.st_ino) : NULL;
        char link[64];
        ssize_t n = -1;
        if (!path && next.fd >= 0) {
            snprintf(link, sizeof(link), "/proc/self/fd/%d", next.fd);
            n = readlink(link, current_path, sizeof(current_path) - 1);
            if (n >= 0) {
                current_path[n] = '\0';
            }
        } else if (path) {
            snprintf(current_path, sizeof(current_path), "%s", path);
            n = (ssize_t)strlen(current_path);
        }
        if (next.fd < 0) {
            // Answered by the reader thread while it waited in the queue
            tell(&next, n >= 0 ? current_path : "a file", next.allowed, next.why);
            continue;
        }
        const char *problem = n < 0 ? "sqwatch cannot name the file" :
                              !path && in_unmarked(current_path) ? "in a directory sqwatch could not mark" :
                              NULL;
        if (!problem && start_decider() != 0) {
            problem = "the command could not be started";
            if (errno != ETIMEDOUT) {
                fprintf(stderr, RED "+ -p: could not start the command: %s\n" RESET,
                        strerror(errno));
            }
        }
        if (problem) {
            pthread_mutex_lock(&queue_lock);
            answer(&current, fail_allow, problem);
            perm_event done = current;
            current_active = 0;
            pthread_mutex_unlock(&queue_lock);
            tell(&done, n >= 0 ? current_path : "a file", done.allowed, done.why);
        }
    }
    if (!decider) {
        // Reap what earlier commands left (sqwatch is their subreaper)
        while (waitpid(-1, NULL, WNOHANG) > 0) {
        }
        return -1;
    }
    pthread_mutex_lock(&queue_lock);
    long long left = current.arrived + timeout_ms - now_ms();
    pthread_mutex_unlock(&queue_lock);
    if (left < 0) {
        left = 0;
    }
    // Without a pidfd the end of the command is looked for every 10 ms
    return decider_pidfd < 0 && left > 10 ? 10 : (int)left;
}

// sqwatch is exiting: stop the reader thread, stop the command deciding an
// event, and answer every event left by the policy: denied, unless -T says
// allow. Closing fanotify then makes the kernel allow anything still on its
// way, which no answer can reach
void perm_shutdown(void) {
    if (fan_fd < 0) {
        return;
    }
    if (write(stop_pipe[1], "x", 1) == 1) {
        pthread_join(reader, NULL);
    }
    if (decider) {
        end_decider(fail_allow, "sqwatch is exiting");
    }
    pthread_mutex_lock(&queue_lock);
    while (queue_count > 0) {
        answer(&queue[queue_head], fail_allow, "sqwatch is exiting");
        queue_head = (queue_head + 1) % QUEUE_SIZE;
        queue_count--;
    }
    pthread_mutex_unlock(&queue_lock);
    close(fan_fd);
    fan_fd = -1;
}
