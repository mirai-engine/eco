#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#if defined(__APPLE__)
#include <sys/event.h>
#include <util.h>
#else
#include <pty.h>
#endif
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include "platform_paths.h"

extern char **environ;
int eco_ring_setup(void);
void eco_ring_forget(int fd);
int eco_ring_poll(int *fds, int *events, int count, int timeout);
int eco_restrict_scope(int scope);

static volatile sig_atomic_t stopping;
static void handle_signal(int sig) { (void)sig; stopping = 1; }

void eco_install_signals(void) {
    struct sigaction action = {0};
    action.sa_handler = handle_signal;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);
}

int eco_stopping(void) { return stopping; }

void eco_listening(int port) {
    fprintf(stderr, "eco-odin listening on UDP %d\n", port);
}

void eco_ring_ready(void) {
    fputs("eco-odin io_uring ready\n", stderr);
}

int eco_wait(int fd, int timeout) {
    struct pollfd p = { .fd = fd, .events = POLLIN };
    int result = poll(&p, 1, timeout);
    return result > 0 && (p.revents & POLLIN) != 0;
}

int eco_socket_fd(uintptr_t socket) { return (int)socket; }

int eco_fd_setup(int fd, int nonblock) {
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) return -1;
    if (!nonblock) return 0;
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#define ECO_POLL_MAX 66

static int poll_portable(int *fds, int *events, int count, int timeout) {
    struct pollfd p[ECO_POLL_MAX];
    for (int i = 0; i < count; i++) {
        p[i] = (struct pollfd){ .fd = fds[i], .events = (short)events[i] };
    }
    int result = poll(p, (nfds_t)count, timeout);
    if (result >= 0) for (int i = 0; i < count; i++) events[i] = p[i].revents;
    return result;
}

#if defined(__APPLE__)
static int queue = -1;
static struct pollfd registered[ECO_POLL_MAX];
static int registered_count;

static void forget_fd(int fd) {
    for (int i = 0; i < registered_count; i++) {
        if (registered[i].fd == fd) {
            registered[i] = registered[--registered_count];
            break;
        }
    }
}

static void kqueue_reset(void) {
    if (queue >= 0) close(queue);
    queue = -1;
    registered_count = 0;
}

static int poll_kqueue(int *fds, int *events, int count, int timeout) {
    if (queue < 0) {
        queue = kqueue();
        if (queue < 0) return -2;
        if (eco_fd_setup(queue, 0) < 0) { kqueue_reset(); return -2; }
    }
    struct kevent changes[ECO_POLL_MAX * 4], ready[ECO_POLL_MAX * 2];
    int nchanges = 0;
    for (int i = 0; i < registered_count; i++) {
        int fd = registered[i].fd;
        int want = 0;
        for (int j = 0; j < count; j++) {
            if (fds[j] == fd) { want = events[j]; break; }
        }
        int remove = registered[i].events & ~want;
        if (remove & POLLIN) EV_SET(&changes[nchanges++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        if (remove & POLLOUT) EV_SET(&changes[nchanges++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    }
    for (int i = 0; i < count; i++) {
        int fd = fds[i];
        if (fd < 0) continue;
        int previous = 0;
        for (int j = 0; j < registered_count; j++) {
            if (registered[j].fd == fd) { previous = registered[j].events; break; }
        }
        int add = events[i] & ~previous;
        if (add & POLLIN) EV_SET(&changes[nchanges++], fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (add & POLLOUT) EV_SET(&changes[nchanges++], fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
    }
    for (int i = 0; i < count; i++) {
        if (fds[i] >= 0 && events[i] == 0) return -2;
    }
    struct timespec delay = {.tv_sec = timeout / 1000, .tv_nsec = (timeout % 1000) * 1000000L};
    int result = kevent(queue, changes, nchanges, ready, ECO_POLL_MAX * 2, timeout < 0 ? NULL : &delay);
    if (result < 0) {
        int interrupted = errno == EINTR;
        kqueue_reset();
        return interrupted ? -1 : -2;
    }
    registered_count = 0;
    for (int i = 0; i < count; i++) {
        if (fds[i] >= 0) {
            registered[registered_count++] = (struct pollfd){.fd = fds[i], .events = (short)events[i]};
        }
    }
    memset(events, 0, (size_t)count * sizeof(*events));
    for (int i = 0; i < result; i++) {
        int fd = (int)ready[i].ident;
        for (int j = 0; j < count; j++) {
            if (fds[j] != fd) continue;
            if (ready[i].filter == EVFILT_READ) events[j] |= POLLIN;
            if (ready[i].filter == EVFILT_WRITE) events[j] |= POLLOUT;
            if (ready[i].flags & EV_EOF) events[j] |= POLLHUP;
            if (ready[i].flags & EV_ERROR) events[j] |= POLLERR;
            break;
        }
    }
    return result;
}
#endif

int eco_poll(int *fds, int *events, int count, int timeout) {
    if (count < 0 || count > ECO_POLL_MAX) return -1;
#if defined(__APPLE__)
    // The small hot path avoids maintaining registrations every time a stream buffer changes.
    if (count >= 8) {
        int result = poll_kqueue(fds, events, count, timeout);
        if (result != -2) return result;
    }
#endif
    int ring_result = eco_ring_poll(fds, events, count, timeout);
    return ring_result == -2 ? poll_portable(fds, events, count, timeout) : ring_result;
}

static int unix_address(struct sockaddr_un *address, const char *name) {
    size_t length = strlen(name);
    if (length == 0 || length >= sizeof(address->sun_path)) return -1;
    memset(address, 0, sizeof(*address));
    address->sun_family = AF_UNIX;
    memcpy(address->sun_path, name, length + 1);
    return 0;
}

int eco_listen_local(const char *name) {
    struct sockaddr_un address;
    if (unix_address(&address, name) < 0) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    mode_t previous = umask(0077);
    int result = bind(fd, (struct sockaddr *)&address, sizeof(address));
    umask(previous);
    if (result < 0) { close(fd); return -1; }
    if (eco_fd_setup(fd, 1) < 0 || listen(fd, 32) < 0) {
        close(fd);
        unlink(name);
        return -1;
    }
    return fd;
}

static int connect_local(const char *name, int nonblock) {
    struct sockaddr_un address;
    if (unix_address(&address, name) < 0) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (eco_fd_setup(fd, nonblock) < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int eco_connect_local(const char *name) { return connect_local(name, 0); }
int eco_try_connect_local(const char *name) { return connect_local(name, 1); }

int eco_accept_local(int listener) {
    int fd = accept(listener, NULL, NULL);
    if (fd < 0) return -1;
    if (eco_fd_setup(fd, 1) < 0) { close(fd); return -1; }
    return fd;
}

// Positive counts are transferred bytes, zero is EOF, -2 is would-block.
int eco_read(int fd, void *buf, int count) {
    ssize_t n;
    do { n = read(fd, buf, (size_t)count); } while (n < 0 && errno == EINTR && !stopping);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -2;
    return (int)n;
}

int eco_write(int fd, const void *buf, int count) {
    ssize_t n;
    do { n = write(fd, buf, (size_t)count); } while (n < 0 && errno == EINTR && !stopping);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -2;
    return (int)n;
}

int eco_close(int fd) {
#if defined(__APPLE__)
    forget_fd(fd);
#endif
    eco_ring_forget(fd);
    return close(fd);
}
int eco_unlink(const char *name) { return unlink(name); }

int eco_root(const char *name) {
    return open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int path_open_error(int dir, const char *name) {
    if (errno == ELOOP) return ECO_PATH_LINK_BLOCKED;
    struct stat st;
    if (errno == ENOTDIR && fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(st.st_mode))
        return ECO_PATH_LINK_BLOCKED;
    return -1;
}

// Walk relative paths with directory handles and forbid symlinks at every level.
int eco_parent(int root, const char *path, char *leaf, int capacity) {
    int dir = fcntl(root, F_DUPFD_CLOEXEC, 3);
    if (dir < 0) return -1;
    const char *p = path;
    for (;;) {
        size_t n = strcspn(p, "/");
        if (n == 0 || n >= (size_t)capacity || (n == 2 && memcmp(p, "..", 2) == 0) ||
            (n == 1 && p[0] == '.' && (p != path || p[n] != '\0'))) break;
        memcpy(leaf, p, n);
        leaf[n] = '\0';
        if (!p[n]) return dir;
        int next = openat(dir, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) next = path_open_error(dir, leaf);
        close(dir);
        if (next < 0) return next;
        dir = next;
        p += n + 1;
    }
    close(dir);
    return -1;
}

int eco_open(int dir, const char *leaf, int want_dir) {
    int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    int fd = openat(dir, leaf, flags | (want_dir ? O_DIRECTORY : 0));
    if (fd < 0) return path_open_error(dir, leaf);
    struct stat st;
    if (fstat(fd, &st) < 0 || (!want_dir && !S_ISREG(st.st_mode))) {
        close(fd);
        return -1;
    }
    return fd;
}

int eco_stat(int dir, const char *leaf, uint64_t *size, uint8_t *kind, uint64_t *stamp) {
    struct stat st;
    if (fstatat(dir, leaf, &st, AT_SYMLINK_NOFOLLOW) < 0) return -1;
    *size = (uint64_t)st.st_size;
    *kind = S_ISREG(st.st_mode) ? 1 : S_ISDIR(st.st_mode) ? 2 : 3;
#if defined(__APPLE__)
    *stamp = (uint64_t)st.st_mtimespec.tv_sec * 1000000000 + (uint64_t)st.st_mtimespec.tv_nsec;
#else
    *stamp = (uint64_t)st.st_mtim.tv_sec * 1000000000 + (uint64_t)st.st_mtim.tv_nsec;
#endif
    return 0;
}

void *eco_directory(int fd) { return fdopendir(fd); }
void eco_dir_close(void *handle) { closedir(handle); }

int eco_dir_next(void *handle, char *out, int capacity) {
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(handle);
        if (entry == NULL) return errno == 0 ? 0 : -1;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        size_t length = strlen(entry->d_name);
        if (length >= (size_t)capacity) return -1;
        memcpy(out, entry->d_name, length);
        return (int)length;
    }
}

int eco_file_create(int dir, const char *name) {
    return openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
}
int eco_rename(int dir, const char *from, const char *to) { return renameat(dir, from, dir, to); }
int eco_remove(int dir, const char *name) { return unlinkat(dir, name, 0); }
int eco_sync(int fd) { return fsync(fd); }

static int open_pipe(int fds[2]) {
    if (pipe(fds) < 0) return -1;
    if (eco_fd_setup(fds[0], 1) < 0 || eco_fd_setup(fds[1], 0) < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    return 0;
}

static void scope_failed(void) {
    static const char message[] = "eco-odin: cannot start sandboxed command\n";
    ssize_t ignored = write(STDERR_FILENO, message, sizeof(message) - 1);
    (void)ignored;
    _exit(126);
}

int eco_spawn(char *const args[], int fds[2], int workdir, int *to_child, int scope) {
    int out[2], err[2], input[2] = {-1, -1};
    if (to_child != NULL) {
        if (pipe(input) < 0) return -1;
        if (eco_fd_setup(input[0], 0) < 0 || eco_fd_setup(input[1], 1) < 0) {
            close(input[0]);
            close(input[1]);
            return -1;
        }
    }
    if (open_pipe(out) < 0) {
        if (to_child != NULL) { close(input[0]); close(input[1]); }
        return -1;
    }
    if (open_pipe(err) < 0) {
        if (to_child != NULL) { close(input[0]); close(input[1]); }
        close(out[0]); close(out[1]);
        return -1;
    }
    if (scope >= 0) {
        pid_t child = fork();
        if (child == 0) {
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
            signal(SIGPIPE, SIG_DFL);
            int in = to_child ? input[0] : open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (dup2(out[1], STDOUT_FILENO) < 0 || dup2(err[1], STDERR_FILENO) < 0 ||
                in < 0 || dup2(in, STDIN_FILENO) < 0 || setpgid(0, 0) < 0 ||
                fchdir(workdir) < 0 || eco_restrict_scope(scope) < 0) scope_failed();
            execvp(args[0], args);
            scope_failed();
        }
        if (child > 0) (void)setpgid(child, child);
        close(out[1]);
        close(err[1]);
        if (to_child) {
            close(input[0]);
            if (child < 0) close(input[1]);
            else *to_child = input[1];
        }
        if (child < 0) { close(out[0]); close(err[0]); }
        else { fds[0] = out[0]; fds[1] = err[0]; }
        return (int)child;
    }

    posix_spawn_file_actions_t files;
    posix_spawnattr_t attr;
    int files_init = posix_spawn_file_actions_init(&files) == 0;
    int attr_init = posix_spawnattr_init(&attr) == 0;
    pid_t pid = -1;
    if (files_init && attr_init) {
        sigset_t sigs, mask;
        sigemptyset(&mask);
        sigemptyset(&sigs);
        sigaddset(&sigs, SIGPIPE);
        if (!posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)
            && !posix_spawnattr_setpgroup(&attr, 0)
            && !posix_spawnattr_setsigdefault(&attr, &sigs)
            && !posix_spawnattr_setsigmask(&attr, &mask)
            && !posix_spawn_file_actions_addfchdir_np(&files, workdir)
            && !(to_child == NULL ?
                posix_spawn_file_actions_addopen(&files, STDIN_FILENO, "/dev/null", O_RDONLY, 0) :
                posix_spawn_file_actions_adddup2(&files, input[0], STDIN_FILENO))
            && !posix_spawn_file_actions_adddup2(&files, out[1], STDOUT_FILENO)
            && !posix_spawn_file_actions_adddup2(&files, err[1], STDERR_FILENO)) {
            if (posix_spawnp(&pid, args[0], &files, &attr, args, environ) != 0) pid = -1;
        }
    }
    if (attr_init) posix_spawnattr_destroy(&attr);
    if (files_init) posix_spawn_file_actions_destroy(&files);
    close(out[1]);
    close(err[1]);
    if (to_child != NULL) {
        close(input[0]);
        if (pid < 0) close(input[1]);
        else *to_child = input[1];
    }
    if (pid < 0) { close(out[0]); close(err[0]); }
    else { fds[0] = out[0]; fds[1] = err[0]; }
    return (int)pid;
}

int eco_child_poll(int pid, uint32_t *status) {
    int code = 0;
    int result = waitpid(pid, &code, WNOHANG);
    if (result < 0 && errno == EINTR) return 0;
    if (result > 0) *status = WIFEXITED(code) ? WEXITSTATUS(code) : 128 + WTERMSIG(code);
    return result;
}

void eco_child_kill(int pid) {
    if (pid <= 0) return;
    kill(-pid, SIGKILL);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
}

#include <sys/file.h>

int eco_lock_local(const char *name) {
    int fd = open(name, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0077) != 0 || flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int eco_check_private_dir(const char *name) {
    struct stat st;
    return lstat(name, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 0077) == 0;
}

int eco_prepare_socket(const char *name) {
    struct stat st;
    if (lstat(name, &st) < 0) return errno == ENOENT ? 0 : -1;
    if (!S_ISSOCK(st.st_mode) || st.st_uid != geteuid()) return -1;
    return unlink(name);
}

int eco_safe_private_file(const char *name) {
    int fd = open(name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0077) != 0 || st.st_size != 32) {
        close(fd);
        return -1;
    }
    return fd;
}

int eco_start_daemon(char *const args[]) {
    pid_t pid = fork();
    if (pid != 0) return (int)pid;
    if (setsid() < 0) _exit(125);
    int null = open("/dev/null", O_RDWR);
    if (null < 0) _exit(125);
    for (int i = 0; i < 3; i++) {
        if (dup2(null, i) < 0) _exit(125);
    }
    if (null > 2) close(null);
    execv(args[0], args);
    _exit(125);
}

int eco_spawn_pty(char *const args[], int *master, int workdir, unsigned short rows, unsigned short cols, int scope) {
    struct winsize size = { .ws_row = rows, .ws_col = cols };
    int fd;
    pid_t pid = forkpty(&fd, NULL, NULL, &size);
    if (pid < 0) return -1;
    if (pid == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGPIPE, SIG_DFL);
        if (fchdir(workdir) < 0 || (scope >= 0 && eco_restrict_scope(scope) < 0)) scope_failed();
        execvp(args[0], args);
        _exit(errno == ENOENT ? 127 : 126);
    }
    if (eco_fd_setup(fd, 1) < 0) {
        close(fd);
        kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        return -1;
    }
    *master = fd;
    return (int)pid;
}

int eco_terminal_resize(int fd, unsigned short rows, unsigned short cols) {
    struct winsize size = { .ws_row = rows, .ws_col = cols };
    return ioctl(fd, TIOCSWINSZ, &size);
}

int eco_terminal_size(int fd, unsigned short *rows, unsigned short *cols) {
    struct winsize size;
    if (ioctl(fd, TIOCGWINSZ, &size) < 0 || !size.ws_row || !size.ws_col) return -1;
    *rows = size.ws_row;
    *cols = size.ws_col;
    return 0;
}

static struct termios saved_terminal;
static int terminal_fd = -1;
void eco_terminal_restore(void) {
    if (terminal_fd >= 0) {
        tcsetattr(terminal_fd, TCSANOW, &saved_terminal);
        terminal_fd = -1;
    }
}
int eco_terminal_raw(int fd) {
    if (terminal_fd >= 0 || tcgetattr(fd, &saved_terminal) < 0) return -1;
    struct termios raw = saved_terminal;
    cfmakeraw(&raw);
    if (tcsetattr(fd, TCSANOW, &raw) < 0) return -1;
    terminal_fd = fd;
    return 0;
}

#include <netdb.h>
#include <netinet/tcp.h>
int eco_net_open(const char *address, int datagram, int *connecting) {
    char host[64];
    const char *port = strrchr(address, ':');
    if (port == NULL || port == address) return -1;
    const char *first = address, *last = port;
    if (*first == '[') {
        first++;
        if (last <= first || last[-1] != ']') return -1;
        last--;
    }
    ptrdiff_t length = last - first;
    if (length <= 0 || length >= (ptrdiff_t)sizeof(host)) return -1;
    memcpy(host, first, (size_t)length);
    host[length] = 0;
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = datagram ? SOCK_DGRAM : SOCK_STREAM,
        .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV,
    };
    struct addrinfo *addr = NULL;
    if (getaddrinfo(host, port + 1, &hints, &addr) != 0) return -1;
    int fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (fd >= 0) {
        *connecting = 0;
        if (eco_fd_setup(fd, 1) < 0) { close(fd); fd = -1; }
        else if (connect(fd, addr->ai_addr, addr->ai_addrlen) < 0) {
            if (errno == EINPROGRESS) *connecting = 1;
            else { close(fd); fd = -1; }
        }
    }
    freeaddrinfo(addr);
    return fd;
}
int eco_net_ready(int fd) {
    struct pollfd p = { .fd = fd, .events = POLLOUT };
    if (poll(&p, 1, 0) <= 0) return 0;
    int error = 0;
    socklen_t size = sizeof(error);
    return getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) < 0 || error ? -1 : 1;
}
int eco_net_fin(int fd) { return shutdown(fd, SHUT_WR); }
int eco_net_recv_datagram(int fd, void *buf, int count) {
    struct iovec iov = {.iov_base = buf, .iov_len = (size_t)count};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
    ssize_t n = recvmsg(fd, &msg, 0);
    if (n >= 0 && (msg.msg_flags & MSG_TRUNC)) return -3;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return -2;
    return (int)n;
}

int eco_start_worker(char *const args[], int scope) {
    pid_t first = fork();
    if (first < 0) return -1;
    if (first == 0) {
        if (scope >= 0 && (dup2(scope, 3) < 0 || fcntl(3, F_SETFD, 0) < 0)) _exit(1);
        pid_t worker = eco_start_daemon(args);
        _exit(worker < 0 ? 1 : 0);
    }
    int status;
    pid_t result;
    do { result = waitpid(first, &status, 0); } while (result < 0 && errno == EINTR);
    return result == first && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int child_events_write = -1;
static void notify_child(int sig) {
    (void)sig;
    int saved = errno;
    const unsigned char event = 1;
    if (child_events_write >= 0) {
        ssize_t ignored = write(child_events_write, &event, 1);
        (void)ignored;
    }
    errno = saved;
}

// Child exit remains observable even if it happens between waitpid and poll.
int eco_child_events(void) {
    int fds[2];
    if (pipe(fds) < 0) return -1;
    if (eco_fd_setup(fds[0], 1) < 0 || eco_fd_setup(fds[1], 1) < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    child_events_write = fds[1];
    struct sigaction action = {0};
    action.sa_handler = notify_child;
    action.sa_flags = SA_NOCLDSTOP;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) < 0) {
        child_events_write = -1;
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    return fds[0];
}

int eco_install_file(const char *part, const char *final) {
    if (link(part, final) == 0) return 0;
    return errno == EEXIST ? 1 : -1;
}

int eco_sync_dir(const char *path) {
    int dir = eco_root(path);
    if (dir < 0) return -1;
    int result = fsync(dir);
    close(dir);
    return result;
}

#include <sys/time.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif

int eco_bulk_socket(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) < 0) return -1;
    struct timeval timeout = {.tv_sec = 15};
    int no_delay = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &no_delay, sizeof(no_delay)) < 0 ||
           setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0 ? -1 : 0;
}

// Return 0 in a worker with exactly socket 3 and its permitted directory 4.
int eco_bulk_worker(int socket, int scope) {
    pid_t worker = fork();
    if (worker != 0) {
        if (worker > 0) (void)setpgid(worker, worker);
        return (int)worker;
    }
    if (setpgid(0, 0) < 0) _exit(125);
    int data = fcntl(socket, F_DUPFD_CLOEXEC, 5);
    int root = fcntl(scope, F_DUPFD_CLOEXEC, 5);
    if (data < 0 || root < 0 || dup2(data, 3) < 0 || dup2(root, 4) < 0) _exit(125);
#if defined(__linux__)
    if (syscall(SYS_close_range, 5u, ~0u, 0u) == 0) return 0;
#endif
    DIR *open_fds = opendir("/dev/fd");
    if (!open_fds) _exit(125);
    int directory = dirfd(open_fds);
    struct dirent *item;
    while ((item = readdir(open_fds)) != NULL) {
        char *end;
        long fd = strtol(item->d_name, &end, 10);
        if (!*end && fd >= 5 && fd != directory) close((int)fd);
    }
    closedir(open_fds);
    return 0;
}
