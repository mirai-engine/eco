#define _GNU_SOURCE
#include <errno.h>

#if defined(__linux__)
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>

static uint64_t handled_files(void) {
    return LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
           LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
           LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
           LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
           LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
           LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
           LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
           LANDLOCK_ACCESS_FS_TRUNCATE;
}

static int permit_fd(int rules, int path, uint64_t rights) {
    struct landlock_path_beneath_attr entry = {.allowed_access = rights, .parent_fd = path};
    return (int)syscall(SYS_landlock_add_rule, rules, LANDLOCK_RULE_PATH_BENEATH, &entry, 0);
}

static int permit_path(int rules, const char *path, uint64_t rights) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    int result = permit_fd(rules, fd, rights);
    close(fd);
    return result;
}

#define DENY_SYSCALL(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

static int restrict_syscalls(void) {
#if defined(__aarch64__)
    const uint32_t audit_arch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
    const uint32_t audit_arch = AUDIT_ARCH_X86_64;
#else
    errno = ENOTSUP;
    return -1;
#endif
    struct sock_filter filters[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, audit_arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        // The x32 ABI shares the audit architecture and uses different syscall numbers.
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
        DENY_SYSCALL(SYS_socket),
        DENY_SYSCALL(SYS_io_uring_setup),
        DENY_SYSCALL(SYS_io_uring_enter),
        DENY_SYSCALL(SYS_io_uring_register),
        DENY_SYSCALL(SYS_ptrace),
        DENY_SYSCALL(SYS_process_vm_readv),
        DENY_SYSCALL(SYS_process_vm_writev),
        DENY_SYSCALL(SYS_pidfd_getfd),
        DENY_SYSCALL(SYS_setsid),
        DENY_SYSCALL(SYS_setpgid),
        DENY_SYSCALL(SYS_unshare),
        DENY_SYSCALL(SYS_setns),
        DENY_SYSCALL(SYS_pidfd_send_signal),
        DENY_SYSCALL(SYS_kill),
        DENY_SYSCALL(SYS_tkill),
        DENY_SYSCALL(SYS_tgkill),
        DENY_SYSCALL(SYS_rt_sigqueueinfo),
        DENY_SYSCALL(SYS_rt_tgsigqueueinfo),
        DENY_SYSCALL(SYS_bpf),
        DENY_SYSCALL(SYS_keyctl),
        DENY_SYSCALL(SYS_add_key),
        DENY_SYSCALL(SYS_request_key),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(filters) / sizeof(filters[0]), .filter = filters};
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

int eco_scope_supported(void) {
    return syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) >= 3;
}

int eco_restrict_scope(int scope) {
    struct landlock_ruleset_attr attributes = {.handled_access_fs = handled_files()};
    int rules = (int)syscall(SYS_landlock_create_ruleset, &attributes, sizeof(attributes), 0);
    if (rules < 0) return -1;

    uint64_t project = attributes.handled_access_fs & ~(LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SOCK);
    uint64_t tools = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    int ok = permit_fd(rules, scope, project) == 0;
    const char *tool_paths[] = {"/usr", "/bin", "/sbin", "/lib", "/lib64"};
    for (size_t i = 0; ok && i < sizeof(tool_paths)/sizeof(tool_paths[0]); i++) {
        ok = permit_path(rules, tool_paths[i], tools) == 0;
    }
    const char *configuration[] = {"/etc/ld.so.cache", "/etc/localtime", "/dev/urandom", "/dev/random", "/dev/zero"};
    for (size_t i = 0; ok && i < sizeof(configuration)/sizeof(configuration[0]); i++) {
        ok = permit_path(rules, configuration[i], LANDLOCK_ACCESS_FS_READ_FILE) == 0;
    }
    if (ok) {
        ok = permit_path(rules, "/dev/null", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE) == 0;
    }
    if (ok) ok = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0;
    if (ok) ok = syscall(SYS_landlock_restrict_self, rules, 0) == 0;
    close(rules);
    if (!ok || restrict_syscalls() < 0) return -1;
    if (syscall(SYS_close_range, 3u, ~0u, 0u) < 0) return -1;
    return clearenv() == 0 && setenv("PATH", "/usr/bin:/bin", 1) == 0 &&
           setenv("HOME", ".", 1) == 0 && setenv("TMPDIR", ".", 1) == 0 ? 0 : -1;
}
#else
int eco_scope_supported(void) { return 0; }
int eco_restrict_scope(int scope) { (void)scope; errno = ENOTSUP; return -1; }
#endif

#if defined(__linux__) && defined(ECO_HAVE_LIBURING)
#include <liburing.h>
#include <poll.h>
#include <string.h>

#define REGISTRATIONS 66
static struct io_uring ring;
static int ring_state;
static int ring_preference;
static uint64_t serial;
static struct entry {
    uint64_t token;
    int fd;
    int mask;
} entries[REGISTRATIONS];

static int enable_ring(void) {
    if (ring_state == 0) ring_state = io_uring_queue_init(256, &ring, 0) == 0 ? 1 : -1;
    return ring_state == 1;
}

int eco_ring_setup(void) {
    const char *configured = getenv("ECO_ODIN_IO_URING");
    if (configured && strcmp(configured, "0") == 0) ring_preference = -1;
    if (configured && strcmp(configured, "1") == 0) ring_preference = 1;
    return ring_preference == 1 && enable_ring();
}

void eco_ring_close(void) {
    if (ring_state == 1) {
        io_uring_queue_exit(&ring);
        ring_state = -1;
    }
}

static int abandon_ring(void) {
    eco_ring_close();
    return -2;
}

static int cancel_entry(struct entry *entry) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (!sqe) return -1;
    io_uring_prep_poll_remove(sqe, entry->token);
    io_uring_sqe_set_data64(sqe, 0);
    entry->token = 0;
    return 0;
}

void eco_ring_forget(int fd) {
    if (ring_state != 1) return;
    for (int i = 0; i < REGISTRATIONS; i++) {
        if (entries[i].token && entries[i].fd == fd) {
            if (cancel_entry(&entries[i]) < 0) (void)abandon_ring();
            else if (io_uring_submit(&ring) < 0) (void)abandon_ring();
            return;
        }
    }
}

int eco_ring_poll(int *fds, int *events, int count, int timeout) {
    if (ring_preference < 0 || (ring_preference == 0 && count < 8) || !enable_ring()) return -2;
    for (int i = 0; i < REGISTRATIONS; i++) {
        struct entry *entry = &entries[i];
        if (!entry->token) continue;
        int found = 0;
        for (int j = 0; j < count; j++) found |= fds[j] == entry->fd && events[j] == entry->mask;
        if (!found && cancel_entry(entry) < 0) return abandon_ring();
    }
    for (int i = 0; i < count; i++) {
        if (fds[i] < 0) continue;
        struct entry *slot = NULL;
        int registered = 0;
        for (int j = 0; j < REGISTRATIONS; j++) {
            if (entries[j].token && entries[j].fd == fds[i]) { registered = 1; break; }
            if (!entries[j].token && !slot) slot = &entries[j];
        }
        if (registered) continue;
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        if (!sqe || !slot) return abandon_ring();
        *slot = (struct entry){.fd = fds[i], .mask = events[i], .token = ++serial};
        io_uring_prep_poll_add(sqe, slot->fd, (unsigned)(slot->mask | POLLERR | POLLHUP));
        io_uring_sqe_set_data64(sqe, slot->token);
    }
    if (io_uring_submit(&ring) < 0) return abandon_ring();

    struct __kernel_timespec delay = {.tv_sec = timeout / 1000, .tv_nsec = (timeout % 1000) * 1000000L};
    struct io_uring_cqe *cqe = NULL;
    int waited = timeout == 0 ? io_uring_peek_cqe(&ring, &cqe) :
        (timeout < 0 ? io_uring_wait_cqe(&ring, &cqe) : io_uring_wait_cqe_timeout(&ring, &cqe, &delay));
    if (waited < 0 && waited != -EINTR && waited != -EAGAIN && waited != -ETIME) return abandon_ring();
    memset(events, 0, (size_t)count * sizeof(*events));
    int ready = 0;
    while (cqe) {
        uint64_t token = io_uring_cqe_get_data64(cqe);
        int result = cqe->res;
        io_uring_cqe_seen(&ring, cqe);
        if (token) {
            for (int i = 0; i < REGISTRATIONS; i++) {
                if (entries[i].token != token) continue;
                for (int j = 0; j < count; j++) {
                    if (fds[j] == entries[i].fd && result != -ECANCELED) {
                        ready += events[j] == 0;
                        events[j] |= result < 0 ? POLLERR : result;
                    }
                }
                entries[i].token = 0;
                break;
            }
        }
        cqe = NULL;
        if (io_uring_peek_cqe(&ring, &cqe) < 0) break;
    }
    return ready;
}
#else
int eco_ring_setup(void) { return 0; }
void eco_ring_close(void) {}
void eco_ring_forget(int fd) { (void)fd; }
int eco_ring_poll(int *fds, int *events, int count, int timeout) {
    (void)fds; (void)events; (void)count; (void)timeout;
    return -2;
}
#endif
