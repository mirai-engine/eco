#include "platform_windows.h"
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FDS 2048
#define PIPE_CAPACITY 8192
static EcoDescriptor *volatile descriptors[MAX_FDS];
static HANDLE completion;
static INIT_ONCE initialized = INIT_ONCE_STATIC_INIT;
static volatile LONG stopping;

static BOOL CALLBACK initialize(PINIT_ONCE once, PVOID parameter, PVOID *context) {
    (void)once; (void)parameter; (void)context;
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data)) return FALSE;
    completion = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    return completion != NULL;
}

HANDLE eco_completion_port(void) {
    if (!InitOnceExecuteOnce(&initialized, initialize, NULL, NULL)) return NULL;
    return completion;
}

void eco_post_wakeup(void) {
    if (completion) PostQueuedCompletionStatus(completion, 0, 0, NULL);
}

void CALLBACK eco_wait_callback(PVOID port, BOOLEAN timed_out) {
    (void)timed_out;
    PostQueuedCompletionStatus(port, 0, 0, NULL);
}

static BOOL WINAPI console_signal(DWORD reason) {
    if (reason != CTRL_C_EVENT && reason != CTRL_BREAK_EVENT) return FALSE;
    InterlockedExchange(&stopping, 1);
    eco_post_wakeup();
    return TRUE;
}

void eco_install_signals(void) {
    (void)eco_completion_port();
    SetConsoleCtrlHandler(console_signal, TRUE);
}
int eco_stopping(void) { return InterlockedCompareExchange(&stopping, 0, 0) != 0; }
void eco_listening(int port) { fprintf(stderr, "eco-odin listening on UDP %d\n", port); }
void eco_ring_ready(void) {}
int eco_ring_setup(void) { return 0; }
void eco_ring_close(void) {}

wchar_t *eco_wide(const char *text) {
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (!length) return NULL;
    wchar_t *converted = malloc((size_t)length * sizeof(*converted));
    if (converted && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, converted, length)) {
        free(converted);
        return NULL;
    }
    return converted;
}

int eco_adopt(EcoDescriptor *entry) {
    if (!entry) return -1;
    for (int i = 3; i < MAX_FDS; ++i) {
        if (!InterlockedCompareExchangePointer((PVOID volatile *)&descriptors[i], entry, NULL)) return i;
    }
    return -1;
}

EcoDescriptor *eco_descriptor(int fd) {
    if (fd < 3 || fd >= MAX_FDS) return NULL;
    return InterlockedCompareExchangePointer((PVOID volatile *)&descriptors[fd], NULL, NULL);
}

static void free_descriptor(EcoDescriptor *entry) {
    free(entry->read_buffer);
    free(entry->write_buffer);
    free(entry->pipe_name);
    free(entry);
}

static void collect(EcoDescriptor *entry) {
    if (entry->closed && !entry->read.pending && !entry->write.pending && !entry->accept.pending) {
        free_descriptor(entry);
    }
}

int eco_file_handle(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) return -1;
    EcoDescriptor *entry = calloc(1, sizeof(*entry));
    if (entry) {
        entry->type = EC_FILE;
        entry->input = entry->output = handle;
        int fd = eco_adopt(entry);
        if (fd >= 0) return fd;
        free(entry);
    }
    CloseHandle(handle);
    return -1;
}

static BOOL associate(HANDLE handle) {
    HANDLE port = eco_completion_port();
    return port && CreateIoCompletionPort(handle, port, 0, 0) == port;
}

int eco_async_pipe(HANDLE input, HANDLE output) {
    EcoDescriptor *entry = calloc(1, sizeof(*entry));
    if (entry) {
        entry->type = EC_PIPE;
        entry->input = input;
        entry->output = output;
        entry->read.owner = entry->write.owner = entry->accept.owner = entry;
        entry->read.kind = EC_READING;
        entry->write.kind = EC_WRITING;
        entry->accept.kind = EC_ACCEPTING;
        entry->nonblocking = TRUE;
        BOOL ok = (!input || associate(input)) &&
                  (!output || input == output || associate(output));
        int fd = ok ? eco_adopt(entry) : -1;
        if (fd >= 0) return fd;
        free_descriptor(entry);
    }
    if (input) CloseHandle(input);
    if (output && input != output) CloseHandle(output);
    return -1;
}

int eco_socket_fd(uintptr_t socket) {
    EcoDescriptor *entry = calloc(1, sizeof(*entry));
    if (!entry) return -1;
    entry->type = EC_SOCKET;
    entry->socket = (SOCKET)socket;
    entry->nonblocking = FALSE;
    int fd = eco_adopt(entry);
    if (fd < 0) free(entry);
    return fd;
}

int eco_close(int fd) {
    if (fd < 3 || fd >= MAX_FDS) return -1;
    EcoDescriptor *entry = InterlockedExchangePointer((PVOID volatile *)&descriptors[fd], NULL);
    if (!entry) return -1;
    entry->closed = TRUE;
    if (entry->wait) UnregisterWaitEx(entry->wait, INVALID_HANDLE_VALUE);
    if (entry->type == EC_SOCKET) {
        closesocket(entry->socket);
        if (entry->event) WSACloseEvent(entry->event);
    } else {
        if (entry->input) {
            CancelIoEx(entry->input, NULL);
            CloseHandle(entry->input);
        }
        if (entry->output && entry->output != entry->input) {
            CancelIoEx(entry->output, NULL);
            CloseHandle(entry->output);
        }
    }
    collect(entry);
    return 0;
}

static BOOL dispatch(DWORD timeout) {
    DWORD bytes = 0;
    ULONG_PTR unused;
    OVERLAPPED *overlapped = NULL;
    BOOL ok = GetQueuedCompletionStatus(eco_completion_port(), &bytes, &unused, &overlapped, timeout);
    if (!overlapped) return ok;
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    EcoIo *operation = CONTAINING_RECORD(overlapped, EcoIo, overlapped);
    EcoDescriptor *entry = operation->owner;
    operation->pending = FALSE;
    if (!entry->closed) {
        switch (operation->kind) {
        case EC_READING:
            entry->read_start = 0;
            entry->read_end = ok ? bytes : 0;
            entry->read_eof = (ok && !bytes) || error == ERROR_BROKEN_PIPE ||
                              error == ERROR_PIPE_NOT_CONNECTED || error == ERROR_HANDLE_EOF;
            entry->read_error = !ok && !entry->read_eof;
            break;
        case EC_WRITING:
            entry->write_done = ok ? bytes : 0;
            entry->write_error = !ok || !bytes;
            break;
        case EC_ACCEPTING:
            entry->connected = ok;
            entry->accept_error = !ok;
            break;
        }
    }
    collect(entry);
    return TRUE;
}

static void drain(void) {
    for (int i = 0; i < 128 && dispatch(0); ++i) {}
}

static void pipe_read(EcoDescriptor *entry) {
    if (!entry->input || entry->read.pending || entry->read_end != entry->read_start ||
        entry->read_eof || entry->read_error) return;
    if (!entry->read_buffer) entry->read_buffer = malloc(PIPE_CAPACITY);
    if (!entry->read_buffer) { entry->read_error = TRUE; return; }
    EcoIo *io = &entry->read;
    memset(&io->overlapped, 0, sizeof(io->overlapped));
    io->pending = TRUE;
    if (!ReadFile(entry->input, entry->read_buffer, PIPE_CAPACITY, NULL, &io->overlapped)) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            io->pending = FALSE;
            entry->read_eof = error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED;
            entry->read_error = !entry->read_eof;
        }
    }
}

static int inherited_read(void *buffer, int count) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (!input || input == INVALID_HANDLE_VALUE) return 0;
    DWORD type = GetFileType(input), bytes;
    if (type == FILE_TYPE_PIPE) {
        DWORD available;
        if (!PeekNamedPipe(input, NULL, 0, NULL, &available, NULL)) {
            DWORD error = GetLastError();
            return error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED ? 0 : -1;
        }
        if (!available) return -2;
        if (available < (DWORD)count) count = (int)available;
    } else if (type == FILE_TYPE_CHAR) {
        DWORD mode;
        if (GetConsoleMode(input, &mode) && WaitForSingleObject(input, 0) != WAIT_OBJECT_0) return -2;
    }
    if (ReadFile(input, buffer, (DWORD)count, &bytes, NULL)) return (int)bytes;
    return GetLastError() == ERROR_BROKEN_PIPE ? 0 : -1;
}

int eco_read(int fd, void *buffer, int count) {
    if (count == 0) return 0;
    if (fd == 0) return inherited_read(buffer, count);
    EcoDescriptor *entry = eco_descriptor(fd);
    if (!entry) return -1;
    if (entry->type == EC_SOCKET) {
        int result = recv(entry->socket, buffer, count, 0);
        if (result >= 0) return result;
        return WSAGetLastError() == WSAEWOULDBLOCK ? -2 : -1;
    }
    if (entry->type == EC_WAKE) return -2;
    if (entry->type != EC_PIPE) {
        DWORD bytes;
        if (ReadFile(entry->input, buffer, (DWORD)count, &bytes, NULL)) return (int)bytes;
        return GetLastError() == ERROR_HANDLE_EOF ? 0 : -1;
    }
    for (;;) {
        pipe_read(entry);
        if (entry->read_end > entry->read_start) {
            DWORD bytes = entry->read_end - entry->read_start;
            if (bytes > (DWORD)count) bytes = (DWORD)count;
            memcpy(buffer, entry->read_buffer + entry->read_start, bytes);
            entry->read_start += bytes;
            return (int)bytes;
        }
        if (entry->read_eof || !entry->input) return 0;
        if (entry->read_error || eco_stopping()) return -1;
        if (entry->nonblocking) return -2;
        (void)dispatch(100);
    }
}

int eco_write(int fd, const void *buffer, int count) {
    if (fd == 1 || fd == 2) {
        DWORD bytes;
        HANDLE output = GetStdHandle(fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
        return WriteFile(output, buffer, (DWORD)count, &bytes, NULL) ? (int)bytes : -1;
    }
    EcoDescriptor *entry = eco_descriptor(fd);
    if (!entry) return -1;
    if (entry->type == EC_SOCKET) {
        int result = send(entry->socket, buffer, count, 0);
        if (result >= 0) return result;
        return WSAGetLastError() == WSAEWOULDBLOCK ? -2 : -1;
    }
    if (count == 0) return 0;
    if (entry->type != EC_PIPE) {
        DWORD bytes;
        return WriteFile(entry->output, buffer, (DWORD)count, &bytes, NULL) ? (int)bytes : -1;
    }
    if (!entry->output) return -1;
    for (;;) {
        if (entry->write_done) {
            DWORD done = entry->write_done;
            entry->write_done = 0;
            return (int)done;
        }
        if (entry->write_error || eco_stopping()) return -1;
        EcoIo *io = &entry->write;
        if (!io->pending) {
            if (!entry->write_buffer) entry->write_buffer = malloc(PIPE_CAPACITY);
            if (!entry->write_buffer) return -1;
            if (count > PIPE_CAPACITY) count = PIPE_CAPACITY;
            memcpy(entry->write_buffer, buffer, (size_t)count);
            memset(&io->overlapped, 0, sizeof(io->overlapped));
            io->pending = TRUE;
            if (!WriteFile(entry->output, entry->write_buffer, (DWORD)count, NULL, &io->overlapped) &&
                GetLastError() != ERROR_IO_PENDING) {
                io->pending = FALSE;
                entry->write_error = TRUE;
                return -1;
            }
        }
        if (entry->nonblocking) return -2;
        (void)dispatch(100);
    }
}

int eco_fd_setup(int fd, int nonblock) {
    EcoDescriptor *entry = eco_descriptor(fd);
    if (!entry) return -1;
    entry->nonblocking = nonblock != 0;
    if (entry->type == EC_SOCKET) {
        u_long enabled = nonblock != 0;
        if (ioctlsocket(entry->socket, FIONBIO, &enabled) != 0) return -1;
        // Windows reports an ICMP port unreachable as a reset on the next receive of a UDP
        // socket; a peer that went away must not interrupt the datagrams of the others.
        int type = 0, size = sizeof(type);
        if (getsockopt(entry->socket, SOL_SOCKET, SO_TYPE, (char *)&type, &size) != 0) return -1;
        if (type == SOCK_DGRAM) {
            BOOL report = FALSE;
            DWORD returned = 0;
            if (WSAIoctl(entry->socket, SIO_UDP_CONNRESET, &report, sizeof(report), NULL, 0,
                         &returned, NULL, NULL) != 0) return -1;
        }
    }
    return 0;
}

static int socket_events(EcoDescriptor *entry, int mask) {
    if (!entry->event) {
        entry->event = WSACreateEvent();
        if (entry->event == WSA_INVALID_EVENT) return ECO_ERR;
        if (WSAEventSelect(entry->socket, entry->event,
                           FD_READ | FD_ACCEPT | FD_WRITE | FD_CONNECT | FD_CLOSE) == SOCKET_ERROR) {
            WSACloseEvent(entry->event);
            entry->event = NULL;
            return ECO_ERR;
        }
    }
    if (WaitForSingleObject(entry->event, 0) == WAIT_OBJECT_0) {
        if (entry->wait) {
            UnregisterWaitEx(entry->wait, INVALID_HANDLE_VALUE);
            entry->wait = NULL;
        }
        WSANETWORKEVENTS event;
        if (WSAEnumNetworkEvents(entry->socket, entry->event, &event)) return ECO_ERR;
        if (event.lNetworkEvents & FD_CONNECT) {
            entry->connecting = FALSE;
            if (event.iErrorCode[FD_CONNECT_BIT]) entry->socket_ready |= ECO_ERR;
        }
        if (event.lNetworkEvents & FD_CLOSE) entry->socket_ready |= ECO_HUP;
    }
    if (!entry->wait && !RegisterWaitForSingleObject(&entry->wait, entry->event, eco_wait_callback,
                    eco_completion_port(), INFINITE, WT_EXECUTEONLYONCE)) return ECO_ERR;
    WSAPOLLFD p = {.fd = entry->socket};
    if (mask & ECO_READ) p.events |= POLLRDNORM;
    if (mask & ECO_WRITE) p.events |= POLLWRNORM;
    if (WSAPoll(&p, 1, 0) == SOCKET_ERROR) return ECO_ERR;
    int result = entry->socket_ready;
    if (p.revents & POLLRDNORM) result |= ECO_READ;
    if (p.revents & POLLWRNORM) result |= ECO_WRITE;
    if (p.revents & POLLERR) result |= ECO_ERR;
    if (p.revents & POLLHUP) result |= ECO_HUP;
    if (p.revents & POLLNVAL) result |= ECO_BAD;
    return result;
}

static int stdin_events(void) {
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    if (!input || input == INVALID_HANDLE_VALUE) return ECO_HUP;
    if (GetFileType(input) == FILE_TYPE_PIPE) {
        DWORD available;
        if (!PeekNamedPipe(input, NULL, 0, NULL, &available, NULL)) return ECO_HUP;
        return available ? ECO_READ : 0;
    }
    DWORD mode;
    if (!GetConsoleMode(input, &mode)) return ECO_READ;
    for (;;) {
        INPUT_RECORD record;
        DWORD got;
        if (!PeekConsoleInputW(input, &record, 1, &got) || !got) return 0;
        if (record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown) return ECO_READ;
        if (!ReadConsoleInputW(input, &record, 1, &got)) return 0;
    }
}

static int descriptor_events(int fd, int mask) {
    if (fd < 0) return 0;
    if (fd == 0) return stdin_events() & (mask | ECO_HUP);
    EcoDescriptor *entry = eco_descriptor(fd);
    if (!entry) return ECO_BAD;
    switch (entry->type) {
    case EC_SOCKET: return socket_events(entry, mask);
    case EC_PIPE: {
        int result = 0;
        if (mask & ECO_READ) {
            pipe_read(entry);
            if (entry->read_end > entry->read_start) result |= ECO_READ;
            if (entry->read_eof) result |= ECO_HUP;
            if (entry->read_error) result |= ECO_ERR;
        }
        if ((mask & ECO_WRITE) && !entry->write.pending) result |= ECO_WRITE;
        if (entry->write_error) result |= ECO_ERR;
        return result;
    }
    case EC_LISTENER: return entry->connected ? ECO_READ : entry->accept_error ? ECO_ERR : 0;
    case EC_WAKE: return 0;
    default: return mask;
    }
}

int eco_poll(int *fds, int *events, int count, int timeout) {
    if (count < 0 || count > 66 || !eco_completion_port()) return -1;
    int masks[66];
    memcpy(masks, events, (size_t)count * sizeof(*events));
    drain();
    int ready = 0;
    for (int i = 0; i < count; ++i) {
        events[i] = descriptor_events(fds[i], masks[i]);
        ready += events[i] != 0;
        // Inherited console/stdio may be a synchronous handle. Bound the check interval.
        if (fds[i] == 0 && (timeout < 0 || timeout > 10)) timeout = 10;
    }
    if (ready || timeout == 0 || eco_stopping()) return ready;
    (void)dispatch(timeout < 0 ? INFINITE : (DWORD)timeout);
    drain();
    for (int i = 0; i < count; ++i) {
        events[i] = descriptor_events(fds[i], masks[i]);
        ready += events[i] != 0;
    }
    return ready;
}
int eco_wait(int fd, int timeout) {
    int event = ECO_READ;
    return eco_poll(&fd, &event, 1, timeout) > 0 && (event & ECO_READ);
}
int eco_child_events(void) {
    EcoDescriptor *entry = calloc(1, sizeof(*entry));
    if (!entry) return -1;
    entry->type = EC_WAKE;
    int fd = eco_adopt(entry);
    if (fd < 0) free(entry);
    return fd;
}

static BOOL token_sid(wchar_t **text) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return FALSE;
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    TOKEN_USER *user = malloc(size);
    BOOL ok = user && GetTokenInformation(token, TokenUser, user, size, &size) &&
              ConvertSidToStringSidW(user->User.Sid, text);
    free(user);
    CloseHandle(token);
    return ok;
}

int eco_default_pipe(char *out, int capacity) {
    wchar_t *sid = NULL;
    if (!token_sid(&sid)) return -1;
    int n = snprintf(out, (size_t)capacity, "\\\\.\\pipe\\eco-odin-%ls", sid);
    LocalFree(sid);
    return n > 0 && n < capacity ? n : -1;
}

int eco_pipe_security(SECURITY_ATTRIBUTES *security, PSECURITY_DESCRIPTOR *descriptor) {
    wchar_t *sid = NULL;
    if (!token_sid(&sid)) return -1;
    wchar_t sddl[384];
    int n = swprintf(sddl, 384, L"O:%lsD:P(A;;GA;;;%ls)(A;;GA;;;SY)", sid, sid);
    LocalFree(sid);
    if (n < 0 || !ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
                                                                      descriptor, NULL)) return -1;
    *security = (SECURITY_ATTRIBUTES){sizeof(*security), *descriptor, FALSE};
    return 0;
}

BOOL eco_private_owner(HANDLE handle, BOOL check_permissions) {
    wchar_t *sid_text = NULL;
    PSID sid = NULL;
    PSID owner = NULL;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR security = NULL;
    BOOL result = token_sid(&sid_text) && ConvertStringSidToSidW(sid_text, &sid) &&
        GetSecurityInfo(handle, GetFileType(handle) == FILE_TYPE_DISK ? SE_FILE_OBJECT : SE_KERNEL_OBJECT,
                        OWNER_SECURITY_INFORMATION |
                        (check_permissions ? DACL_SECURITY_INFORMATION : 0),
                        &owner, NULL, &dacl, NULL, &security) == ERROR_SUCCESS &&
        owner && EqualSid(owner, sid);
    if (result && check_permissions) {
        result = dacl != NULL;
        for (DWORD i = 0; result && i < dacl->AceCount; ++i) {
            ACE_HEADER *header = NULL;
            if (!GetAce(dacl, i, (void **)&header) || !header) { result = FALSE; break; }
            if (header->AceFlags & INHERIT_ONLY_ACE) continue;
            if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) { result = FALSE; break; }
            ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)header;
            PSID grantee = &ace->SidStart;
            result = EqualSid(grantee, sid) || IsWellKnownSid(grantee, WinLocalSystemSid) ||
                     IsWellKnownSid(grantee, WinBuiltinAdministratorsSid);
        }
    }
    if (sid_text) LocalFree(sid_text);
    if (sid) LocalFree(sid);
    if (security) LocalFree(security);
    return result;
}

static HANDLE local_instance(const wchar_t *name, BOOL first) {
    SECURITY_ATTRIBUTES security;
    PSECURITY_DESCRIPTOR descriptor;
    if (eco_pipe_security(&security, &descriptor) < 0) return INVALID_HANDLE_VALUE;
    HANDLE pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                                  (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                                  PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                  PIPE_UNLIMITED_INSTANCES, PIPE_CAPACITY, PIPE_CAPACITY, 0, &security);
    LocalFree(descriptor);
    return pipe;
}

static void start_accept(EcoDescriptor *entry) {
    EcoIo *io = &entry->accept;
    memset(&io->overlapped, 0, sizeof(io->overlapped));
    io->pending = TRUE;
    if (!ConnectNamedPipe(entry->input, &io->overlapped)) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            io->pending = FALSE;
            entry->connected = error == ERROR_PIPE_CONNECTED;
            entry->accept_error = !entry->connected;
        }
    }
}

int eco_listen_local(const char *name) {
    wchar_t *wide = eco_wide(name);
    if (!wide) return -1;
    HANDLE pipe = local_instance(wide, TRUE);
    if (pipe == INVALID_HANDLE_VALUE) { free(wide); return -1; }
    int fd = eco_async_pipe(pipe, pipe);
    EcoDescriptor *entry = eco_descriptor(fd);
    if (!entry) { free(wide); return -1; }
    entry->type = EC_LISTENER;
    entry->pipe_name = wide;
    start_accept(entry);
    if (!entry->accept_error) return fd;
    eco_close(fd);
    return -1;
}

int eco_connect_local(const char *name) {
    wchar_t *wide = eco_wide(name);
    if (!wide) return -1;
    // Use data rights without FILE_CREATE_PIPE_INSTANCE or security-changing access.
    HANDLE pipe = CreateFileW(wide, FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES |
                              READ_CONTROL | SYNCHRONIZE, 0, NULL, OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    free(wide);
    if (pipe == INVALID_HANDLE_VALUE) return -1;
    if (!eco_private_owner(pipe, TRUE)) { CloseHandle(pipe); return -1; }
    int fd = eco_async_pipe(pipe, pipe);
    if (fd >= 0) eco_descriptor(fd)->nonblocking = FALSE;
    return fd;
}

int eco_accept_local(int listener) {
    EcoDescriptor *entry = eco_descriptor(listener);
    if (!entry || entry->type != EC_LISTENER) return -1;
    drain();
    if (entry->accept_error) {
        HANDLE replacement = local_instance(entry->pipe_name, FALSE);
        if (replacement != INVALID_HANDLE_VALUE) {
            if (associate(replacement)) {
                CloseHandle(entry->input);
                entry->input = entry->output = replacement;
                entry->accept_error = FALSE;
                start_accept(entry);
            } else CloseHandle(replacement);
        }
    }
    if (!entry->connected) return -1;
    HANDLE replacement = local_instance(entry->pipe_name, FALSE);
    if (replacement == INVALID_HANDLE_VALUE) return -1;
    if (!associate(replacement)) { CloseHandle(replacement); return -1; }

    // The accepted instance is already associated. Move it without re-associating.
    EcoDescriptor *accepted = calloc(1, sizeof(*accepted));
    if (!accepted) { CloseHandle(replacement); return -1; }
    accepted->type = EC_PIPE;
    accepted->input = accepted->output = entry->input;
    accepted->nonblocking = TRUE;
    accepted->read.owner = accepted->write.owner = accepted;
    accepted->read.kind = EC_READING;
    accepted->write.kind = EC_WRITING;
    int fd = eco_adopt(accepted);
    if (fd < 0) { free(accepted); CloseHandle(replacement); return -1; }

    entry->input = entry->output = replacement;
    entry->connected = FALSE;
    start_accept(entry);
    return fd;
}

int eco_prepare_socket(const char *name) { (void)name; return 0; }
int eco_unlink(const char *name) { (void)name; return 0; }

int eco_spawn_pipe(BOOL host_reads, int *host_fd, HANDLE *child) {
    static volatile LONG sequence;
    wchar_t name[128];
    if (swprintf(name, 128, L"\\\\.\\pipe\\eco-odin-child-%lu-%ld", GetCurrentProcessId(),
                 InterlockedIncrement(&sequence)) < 0) return -1;
    SECURITY_ATTRIBUTES security;
    PSECURITY_DESCRIPTOR descriptor;
    if (eco_pipe_security(&security, &descriptor) < 0) return -1;
    HANDLE host = CreateNamedPipeW(name, (host_reads ? PIPE_ACCESS_INBOUND : PIPE_ACCESS_OUTBOUND) |
                                   FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                   PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                                   1, PIPE_CAPACITY, PIPE_CAPACITY, 0, &security);
    LocalFree(descriptor);
    if (host == INVALID_HANDLE_VALUE) return -1;
    HANDLE peer = CreateFileW(name, host_reads ? GENERIC_WRITE : GENERIC_READ, 0, NULL,
                              OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    if (peer == INVALID_HANDLE_VALUE) { CloseHandle(host); return -1; }
    OVERLAPPED connect = {0};
    connect.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!connect.hEvent) { CloseHandle(peer); CloseHandle(host); return -1; }
    BOOL connected = ConnectNamedPipe(host, &connect);
    if (!connected) {
        DWORD error = GetLastError();
        DWORD ignored = 0;
        connected = error == ERROR_PIPE_CONNECTED ||
                    (error == ERROR_IO_PENDING && GetOverlappedResult(host, &connect, &ignored, TRUE));
    }
    CloseHandle(connect.hEvent);
    if (!connected) { CloseHandle(peer); CloseHandle(host); return -1; }

    int fd = eco_async_pipe(host_reads ? host : NULL, host_reads ? NULL : host);
    if (fd < 0) { CloseHandle(peer); return -1; }
    *host_fd = fd;
    *child = peer;
    return 0;
}

int eco_net_open(const char *address, int datagram, int *connecting) {
    if (!eco_completion_port()) return -1;
    char host[128];
    const char *port = strrchr(address, ':');
    if (!port || port == address) return -1;
    const char *begin = address, *end = port;
    if (*begin == '[') {
        ++begin;
        if (end <= begin || end[-1] != ']') return -1;
        --end;
    }
    size_t n = (size_t)(end - begin);
    if (!n || n >= sizeof(host)) return -1;
    memcpy(host, begin, n);
    host[n] = 0;
    struct addrinfo hints = {.ai_family = AF_UNSPEC,
        .ai_socktype = datagram ? SOCK_DGRAM : SOCK_STREAM,
        .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV};
    struct addrinfo *result = NULL;
    if (getaddrinfo(host, port+1, &hints, &result)) return -1;
    SOCKET socket_handle = WSASocketW(result->ai_family, result->ai_socktype, result->ai_protocol,
                                     NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    int fd = -1;
    if (socket_handle != INVALID_SOCKET) {
        fd = eco_socket_fd((uintptr_t)socket_handle);
        if (fd < 0) closesocket(socket_handle);
        else if (eco_fd_setup(fd, 1) < 0) { eco_close(fd); fd = -1; }
        else {
            *connecting = 0;
            if (connect(socket_handle, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
                int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS) {
                    *connecting = 1;
                    eco_descriptor(fd)->connecting = TRUE;
                } else { eco_close(fd); fd = -1; }
            }
        }
    }
    freeaddrinfo(result);
    return fd;
}

int eco_net_ready(int fd) {
    EcoDescriptor *entry = eco_descriptor(fd);
    if (!entry || entry->type != EC_SOCKET) return -1;
    int state = socket_events(entry, ECO_WRITE);
    if (state & (ECO_ERR | ECO_BAD | ECO_HUP)) return -1;
    if (!(state & ECO_WRITE)) return 0;
    int status = 0, length = sizeof(status);
    return getsockopt(entry->socket, SOL_SOCKET, SO_ERROR, (char *)&status, &length) || status ? -1 : 1;
}
int eco_net_fin(int fd) {
    EcoDescriptor *entry = eco_descriptor(fd);
    return entry && entry->type == EC_SOCKET ? shutdown(entry->socket, SD_SEND) : -1;
}
int eco_net_recv_datagram(int fd, void *buffer, int count) {
    EcoDescriptor *entry = eco_descriptor(fd);
    if (!entry || entry->type != EC_SOCKET) return -1;
    int n = recv(entry->socket, buffer, count, 0);
    if (n >= 0) return n;
    int error = WSAGetLastError();
    return error == WSAEWOULDBLOCK ? -2 : error == WSAEMSGSIZE ? -3 : -1;
}

int eco_bulk_socket(int fd) {
    EcoDescriptor *entry = eco_descriptor(fd);
    if (!entry || entry->type != EC_SOCKET) return -1;
    if (entry->wait) { UnregisterWaitEx(entry->wait, INVALID_HANDLE_VALUE); entry->wait = NULL; }
    if (entry->event) {
        if (WSAEventSelect(entry->socket, NULL, 0) == SOCKET_ERROR) return -1;
        WSACloseEvent(entry->event);
        entry->event = NULL;
    }
    int yes = 1, time = 15000;
    return eco_fd_setup(fd, 0) < 0 ||
           setsockopt(entry->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&yes, sizeof(yes)) ||
           setsockopt(entry->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&time, sizeof(time)) ||
           setsockopt(entry->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&time, sizeof(time)) ? -1 : 0;
}

int eco_scope_supported(void) { return 0; }
