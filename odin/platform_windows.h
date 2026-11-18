#ifndef ECO_PLATFORM_WINDOWS_H
#define ECO_PLATFORM_WINDOWS_H
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>

enum { ECO_READ = 1, ECO_WRITE = 4, ECO_ERR = 8, ECO_HUP = 16, ECO_BAD = 32 };
enum { EC_FILE, EC_SOCKET, EC_PIPE, EC_LISTENER, EC_WAKE };

typedef struct EcoDescriptor EcoDescriptor;
typedef struct EcoIo {
    OVERLAPPED overlapped;
    EcoDescriptor *owner;
    enum { EC_READING, EC_WRITING, EC_ACCEPTING } kind;
    BOOL pending;
} EcoIo;

struct EcoDescriptor {
    int type;
    HANDLE input, output, event, wait;
    SOCKET socket;
    int socket_ready;
    BOOL nonblocking, closed, connecting;
    BOOL read_eof, read_error, write_error, connected, accept_error;
    DWORD read_start, read_end, write_done;
    EcoIo read, write, accept;
    unsigned char *read_buffer, *write_buffer;
    wchar_t *pipe_name;
    HPCON terminal;
};

HANDLE eco_completion_port(void);
int eco_adopt(EcoDescriptor *entry);
EcoDescriptor *eco_descriptor(int fd);
int eco_file_handle(HANDLE handle);
int eco_async_pipe(HANDLE input, HANDLE output);
int eco_spawn_pipe(BOOL host_reads, int *host_fd, HANDLE *child);
int eco_close(int fd);
wchar_t *eco_wide(const char *text);
wchar_t *eco_handle_path(HANDLE handle);
int eco_pipe_security(SECURITY_ATTRIBUTES *security, PSECURITY_DESCRIPTOR *descriptor);
BOOL eco_private_owner(HANDLE handle, BOOL check_permissions);
void eco_post_wakeup(void);
void CALLBACK eco_wait_callback(PVOID port, BOOLEAN timed_out);
#endif
