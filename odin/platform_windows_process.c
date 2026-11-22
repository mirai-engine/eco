#include "platform_windows.h"
#include <stdlib.h>
#include <wchar.h>

#define CHILDREN 1024
#define COMMAND_CAPACITY 32767

typedef struct EcoChild {
    HANDLE process, job, wait;
    HPCON terminal;
    int terminal_fd, socket_fd;
} EcoChild;
static EcoChild children[CHILDREN];

typedef struct EcoCommand {
    wchar_t *text;
    size_t size;
} EcoCommand;

static BOOL put(EcoCommand *line, wchar_t c, size_t repeat) {
    if (repeat >= COMMAND_CAPACITY - line->size) return FALSE;
    while (repeat--) line->text[line->size++] = c;
    return TRUE;
}

static wchar_t *command_line(char *const args[]) {
    EcoCommand line = {.text = malloc(COMMAND_CAPACITY * sizeof(wchar_t))};
    if (!line.text) return NULL;
    for (int i = 0; args[i]; ++i) {
        wchar_t *argument = eco_wide(args[i]);
        if (!argument) { free(line.text); return NULL; }
        BOOL quoted = !*argument || wcspbrk(argument, L" \t\"");
        BOOL ok = (!i || put(&line, L' ', 1)) && (!quoted || put(&line, L'"', 1));
        size_t slashes = 0;
        for (const wchar_t *p = argument; ok; ++p) {
            if (*p == L'\\') { ++slashes; continue; }
            if (!*p) {
                ok = put(&line, L'\\', quoted ? slashes * 2 : slashes) &&
                     (!quoted || put(&line, L'"', 1));
                break;
            }
            if (*p == L'"') slashes = slashes * 2 + 1;
            ok = put(&line, L'\\', slashes) && put(&line, *p, 1);
            slashes = 0;
        }
        free(argument);
        if (!ok) { free(line.text); return NULL; }
    }
    line.text[line.size] = 0;
    return line.text;
}

static DWORD WINAPI close_console(void *value) {
    ClosePseudoConsole((HPCON)value);
    return 0;
}

static void release_console(HPCON terminal) {
    // Older Windows releases may block while ConPTY sends its final output.
    if (terminal && !QueueUserWorkItem(close_console, terminal, WT_EXECUTELONGFUNCTION)) {
        HANDLE thread = CreateThread(NULL, 0, close_console, terminal, 0, NULL);
        if (thread) CloseHandle(thread);
    }
}

static void release_child(EcoChild *child) {
    if (child->wait) UnregisterWaitEx(child->wait, INVALID_HANDLE_VALUE);
    if (child->job) CloseHandle(child->job);
    if (child->socket_fd >= 0) eco_close(child->socket_fd);
    EcoDescriptor *terminal = eco_descriptor(child->terminal_fd);
    if (terminal && terminal->terminal == child->terminal) terminal->terminal = NULL;
    release_console(child->terminal);
    CloseHandle(child->process);
    *child = (EcoChild){0};
}

static int track(HANDLE process, HANDLE job, HPCON terminal, int terminal_fd, int socket_fd) {
    HANDLE port = eco_completion_port();
    for (int i = 1; port && i < CHILDREN; ++i) {
        if (children[i].process) continue;
        EcoChild *child = &children[i];
        *child = (EcoChild){.process = process, .job = job, .terminal = terminal,
                            .terminal_fd = terminal_fd, .socket_fd = socket_fd};
        if (RegisterWaitForSingleObject(&child->wait, process, eco_wait_callback, port,
                                        INFINITE, WT_EXECUTEONLYONCE)) return i;
        *child = (EcoChild){0};
        break;
    }
    return -1;
}

int eco_child_poll(int id, uint32_t *status) {
    if (id <= 0 || id >= CHILDREN || !children[id].process) return -1;
    EcoChild *child = &children[id];
    DWORD wait = WaitForSingleObject(child->process, 0);
    if (wait == WAIT_TIMEOUT) return 0;
    if (wait != WAIT_OBJECT_0) return -1;
    DWORD code = 0;
    BOOL ok = child->socket_fd >= 0 ? GetExitCodeThread(child->process, &code) :
                                      GetExitCodeProcess(child->process, &code);
    *status = ok ? code : 125;
    release_child(child);
    return ok ? id : -1;
}

void eco_child_kill(int id) {
    if (id <= 0 || id >= CHILDREN || !children[id].process) return;
    EcoChild *child = &children[id];
    if (child->socket_fd >= 0) {
        EcoDescriptor *socket = eco_descriptor(child->socket_fd);
        if (socket) shutdown(socket->socket, SD_BOTH);
        CancelSynchronousIo(child->process);
    } else if (child->job) TerminateJobObject(child->job, 130);
    else TerminateProcess(child->process, 130);
    WaitForSingleObject(child->process, INFINITE);
    release_child(child);
}

static HANDLE create_process(char *const args[], const wchar_t *directory, HANDLE handles[3],
                             HPCON terminal, DWORD flags, HANDLE *job_out) {
    STARTUPINFOEXW startup = {.StartupInfo = {.cb = sizeof(startup)}};
    SIZE_T need = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &need);
    startup.lpAttributeList = malloc(need);
    if (!startup.lpAttributeList) return NULL;
    BOOL initialized = InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &need);
    BOOL ok = initialized;
    if (ok && terminal) {
        ok = UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                       terminal, sizeof(terminal), NULL, NULL);
        // Null standard handles make the child attach to the pseudoconsole instead of copying
        // this process's redirected handle values, which it does not inherit.
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    } else if (ok) {
        for (int i = 0; i < 3 && ok; ++i) {
            ok = SetHandleInformation(handles[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        ok = ok && UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                             handles, sizeof(HANDLE)*3, NULL, NULL);
    }

    HANDLE job = NULL;
    if (ok && job_out) {
        // Kills the tree when the command ends, except a process created with
        // CREATE_BREAKAWAY_FROM_JOB, which asked to outlive it (a detached server or editor).
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit = {0};
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                                 JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        job = CreateJobObjectW(NULL, NULL);
        ok = job && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limit, sizeof(limit));
    }
    wchar_t *line = ok ? command_line(args) : NULL;
    PROCESS_INFORMATION process = {0};
    BOOL started = line && CreateProcessW(NULL, line, NULL, NULL, !terminal,
                                         flags | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                                         NULL, directory, &startup.StartupInfo, &process);
    free(line);
    if (initialized) DeleteProcThreadAttributeList(startup.lpAttributeList);
    free(startup.lpAttributeList);
    if (!started) {
        if (job) CloseHandle(job);
        return NULL;
    }
    ok = (!job || AssignProcessToJobObject(job, process.hProcess)) &&
         ResumeThread(process.hThread) != (DWORD)-1;
    CloseHandle(process.hThread);
    if (!ok) {
        TerminateProcess(process.hProcess, 125);
        CloseHandle(process.hProcess);
        if (job) CloseHandle(job);
        return NULL;
    }
    if (job_out) *job_out = job;
    return process.hProcess;
}

static HANDLE null_file(DWORD access) {
    HANDLE result = CreateFileW(L"NUL", access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return result == INVALID_HANDLE_VALUE ? NULL : result;
}

static void close_handles(HANDLE handles[3]) {
    for (int i = 0; i < 3; ++i) if (handles[i]) CloseHandle(handles[i]);
}

int eco_spawn(char *const args[], int fds[2], int workdir, int *to_child, int scope) {
    if (scope >= 0) return -1;
    EcoDescriptor *dir = eco_descriptor(workdir);
    wchar_t *directory = dir ? eco_working_directory(dir->input) : NULL;
    if (!directory) return -1;
    HANDLE handles[3] = {0}, job = NULL;
    int host[3] = {-1, -1, -1};
    int id = -1;
    if (to_child) {
        if (eco_spawn_pipe(FALSE, &host[0], &handles[0]) < 0) goto cleanup;
    } else handles[0] = null_file(GENERIC_READ);
    if (!handles[0] ||
        eco_spawn_pipe(TRUE, &host[1], &handles[1]) < 0 ||
        eco_spawn_pipe(TRUE, &host[2], &handles[2]) < 0) goto cleanup;

    HANDLE process = create_process(args, directory, handles, NULL, CREATE_NO_WINDOW, &job);
    if (!process) goto cleanup;
    id = track(process, job, NULL, -1, -1);
    if (id < 0) { CloseHandle(job); CloseHandle(process); goto cleanup; }
    fds[0] = host[1];
    fds[1] = host[2];
    if (to_child) *to_child = host[0];
 cleanup:
    close_handles(handles);
    if (id < 0) { for (int i = 0; i < 3; ++i) if (host[i] >= 0) eco_close(host[i]); }
    free(directory);
    return id;
}

int eco_spawn_pty(char *const args[], int *master, int workdir, unsigned short rows,
                 unsigned short cols, int scope) {
    if (scope >= 0 || !rows || !cols || rows > SHRT_MAX || cols > SHRT_MAX) return -1;
    EcoDescriptor *dir = eco_descriptor(workdir);
    wchar_t *directory = dir ? eco_working_directory(dir->input) : NULL;
    if (!directory) return -1;

    int input = -1, output = -1, id = -1;
    HANDLE handles[3] = {0}, job = NULL;
    HPCON console = NULL;
    if (eco_spawn_pipe(FALSE, &input, &handles[0]) < 0 ||
        eco_spawn_pipe(TRUE, &output, &handles[1]) < 0) goto cleanup;
    if (FAILED(CreatePseudoConsole((COORD){(SHORT)cols, (SHORT)rows}, handles[0], handles[1], 0, &console)))
        goto cleanup;

    HANDLE process = create_process(args, directory, handles, console, 0, &job);
    if (!process) goto cleanup;
    id = track(process, job, console, output, -1);
    if (id < 0) { CloseHandle(job); CloseHandle(process); goto cleanup; }

    EcoDescriptor *read_side = eco_descriptor(output), *write_side = eco_descriptor(input);
    read_side->output = write_side->output;
    write_side->output = NULL;
    read_side->terminal = console;
    *master = output;
 cleanup:
    close_handles(handles);
    if (input >= 0) eco_close(input);
    if (id < 0) {
        if (output >= 0) eco_close(output);
        release_console(console);
    }
    free(directory);
    return id;
}

int eco_terminal_resize(int fd, unsigned short rows, unsigned short cols) {
    EcoDescriptor *entry = eco_descriptor(fd);
    return entry && entry->terminal && rows && cols && rows <= SHRT_MAX && cols <= SHRT_MAX &&
           SUCCEEDED(ResizePseudoConsole(entry->terminal, (COORD){(SHORT)cols, (SHORT)rows})) ? 0 : -1;
}

int eco_terminal_size(int fd, unsigned short *rows, unsigned short *cols) {
    (void)fd;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (!GetConsoleScreenBufferInfo(output, &info)) return -1;
    *rows = (unsigned short)(info.srWindow.Bottom - info.srWindow.Top + 1);
    *cols = (unsigned short)(info.srWindow.Right - info.srWindow.Left + 1);
    return *rows && *cols ? 0 : -1;
}

static DWORD saved_input_mode, saved_output_mode;
static UINT saved_input_cp, saved_output_cp;
static BOOL raw_console;

int eco_terminal_raw(int fd) {
    (void)fd;
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE), output = GetStdHandle(STD_OUTPUT_HANDLE);
    if (raw_console || !GetConsoleMode(input, &saved_input_mode) ||
        !GetConsoleMode(output, &saved_output_mode)) return -1;
    DWORD mode = (saved_input_mode | ENABLE_VIRTUAL_TERMINAL_INPUT) &
                    ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
    if (!SetConsoleMode(input, mode)) return -1;
    if (!SetConsoleMode(output, saved_output_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        SetConsoleMode(input, saved_input_mode);
        return -1;
    }
    saved_input_cp = GetConsoleCP();
    saved_output_cp = GetConsoleOutputCP();
    if (!SetConsoleCP(CP_UTF8) || !SetConsoleOutputCP(CP_UTF8)) {
        SetConsoleCP(saved_input_cp);
        SetConsoleOutputCP(saved_output_cp);
        SetConsoleMode(input, saved_input_mode);
        SetConsoleMode(output, saved_output_mode);
        return -1;
    }
    raw_console = TRUE;
    return 0;
}

void eco_terminal_restore(void) {
    if (!raw_console) return;
    SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), saved_input_mode);
    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), saved_output_mode);
    SetConsoleCP(saved_input_cp);
    SetConsoleOutputCP(saved_output_cp);
    raw_console = FALSE;
}

static HANDLE detached(char *const args[]) {
    HANDLE handles[3] = {null_file(GENERIC_READ), null_file(GENERIC_WRITE), null_file(GENERIC_WRITE)};
    HANDLE process = NULL;
    if (handles[0] && handles[1] && handles[2]) {
        // Leave a job this process runs in, so that the job's end does not end it; a job that
        // forbids breakaway rejects the request and keeps the process.
        const DWORD flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
        process = create_process(args, NULL, handles, NULL, flags | CREATE_BREAKAWAY_FROM_JOB, NULL);
        if (!process) process = create_process(args, NULL, handles, NULL, flags, NULL);
    }
    close_handles(handles);
    return process;
}

int eco_start_daemon(char *const args[]) {
    HANDLE process = detached(args);
    if (!process) return -1;
    int id = track(process, NULL, NULL, -1, -1);
    if (id < 0) CloseHandle(process);
    return id;
}

int eco_start_worker(char *const args[], int scope) {
    if (scope >= 0) return -1;
    HANDLE process = detached(args);
    if (!process) return -1;
    CloseHandle(process);
    return 0;
}

int eco_dup_file(int fd) {
    EcoDescriptor *entry = eco_descriptor(fd);
    HANDLE copy;
    if (!entry || entry->type != EC_FILE ||
        !DuplicateHandle(GetCurrentProcess(), entry->input, GetCurrentProcess(), &copy, 0,
                        FALSE, DUPLICATE_SAME_ACCESS)) return -1;
    return eco_file_handle(copy);
}

typedef void (*EcoWork)(void *);
typedef struct EcoThread {
    EcoWork run;
    void *data;
} EcoThread;

static DWORD WINAPI thread_main(void *data) {
    EcoThread work = *(EcoThread *)data;
    free(data);
    work.run(work.data);
    return 0;
}

int eco_bulk_thread(EcoWork work, void *data, int socket_fd) {
    EcoThread *start = malloc(sizeof(*start));
    if (!start) return -1;
    *start = (EcoThread){work, data};
    HANDLE thread = CreateThread(NULL, 0, thread_main, start, CREATE_SUSPENDED, NULL);
    if (!thread) { free(start); return -1; }
    int id = track(thread, NULL, NULL, -1, socket_fd);
    if (id < 0 || ResumeThread(thread) == (DWORD)-1) {
        TerminateThread(thread, 125); // The worker is still suspended and has acquired no resources.
        if (id >= 0) {
            children[id].socket_fd = -1; // Ownership remains with the caller.
            release_child(&children[id]);
        } else CloseHandle(thread);
        free(start);
        return -1;
    }
    return id;
}

static BOOL git_bash(wchar_t path[MAX_PATH], const wchar_t *base, const wchar_t *tail) {
    size_t length = wcslen(base), extra = wcslen(tail);
    if (!length || length + extra >= MAX_PATH) return FALSE;
    wmemcpy(path, base, length);
    wmemcpy(path + length, tail, extra + 1);
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

// Git Bash's bin\bash.exe puts the Git tools on PATH. A bare bash.exe on PATH can be the WSL one
// in System32, so the search starts from git.exe, which lives in Git\cmd, Git\bin or
// Git\mingw64\bin, and then tries the machine and per-user install folders.
int eco_posix_shell(char *buffer, int capacity) {
    wchar_t path[MAX_PATH], git[MAX_PATH];
    BOOL found = FALSE;
    DWORD size = GetEnvironmentVariableW(L"PATH", NULL, 0);
    wchar_t *search = size ? malloc(size * sizeof(wchar_t)) : NULL;
    DWORD length = search && GetEnvironmentVariableW(L"PATH", search, size) == size - 1
        ? SearchPathW(search, L"git.exe", NULL, MAX_PATH, git, NULL) : 0;
    free(search);
    for (int up = 0; length && length < MAX_PATH && !found && up < 3; ++up) {
        wchar_t *slash = wcsrchr(git, L'\\');
        if (!slash) break;
        *slash = 0;
        found = up && git_bash(path, git, L"\\bin\\bash.exe");
    }
    static const wchar_t *const variables[] = {L"ProgramW6432", L"ProgramFiles", L"LOCALAPPDATA"};
    static const wchar_t *const folders[] = {L"\\Git\\bin\\bash.exe", L"\\Git\\bin\\bash.exe",
                                             L"\\Programs\\Git\\bin\\bash.exe"};
    for (int i = 0; !found && i < 3; ++i) {
        length = GetEnvironmentVariableW(variables[i], git, MAX_PATH);
        found = length && length < MAX_PATH && git_bash(path, git, folders[i]);
    }
    if (!found) return -1;
    int written = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, buffer, capacity, NULL, NULL);
    return written > 0 ? written - 1 : -1;
}
