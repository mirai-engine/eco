#include "platform_windows.h"
#include <winternl.h>
#include <stdlib.h>
#include <string.h>

#ifndef OBJ_DONT_REPARSE
#define OBJ_DONT_REPARSE 0x00001000L
#endif
#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 1
#endif
#ifndef FILE_CREATE
#define FILE_CREATE 2
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 1
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x40
#endif

typedef NTSTATUS (NTAPI *NtCreateFileFn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtSetInformationFileFn)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS);

static NtCreateFileFn nt_create(void) {
    return (NtCreateFileFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
}
static NtSetInformationFileFn nt_set(void) {
    return (NtSetInformationFileFn)(void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile");
}

static DWORD attributes(HANDLE handle) {
    FILE_ATTRIBUTE_TAG_INFO info;
    if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info))) return INVALID_FILE_ATTRIBUTES;
    return info.FileAttributes;
}

static HANDLE valid_handle(HANDLE handle, int directory) {
    if (handle == INVALID_HANDLE_VALUE) return handle;
    DWORD attrs = attributes(handle);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_REPARSE_POINT) ||
        (directory >= 0 && ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory)) {
        CloseHandle(handle);
        return INVALID_HANDLE_VALUE;
    }
    return handle;
}

static HANDLE local_handle_wide(const wchar_t *path, DWORD access, DWORD disposition,
                                SECURITY_ATTRIBUTES *security, int directory) {
    HANDLE handle = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                security, disposition, FILE_FLAG_OPEN_REPARSE_POINT |
                                (directory == 1 ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL), NULL);
    return valid_handle(handle, directory);
}

static HANDLE local_handle(const char *name, DWORD access, DWORD disposition, SECURITY_ATTRIBUTES *security,
                           int directory) {
    wchar_t *path = eco_wide(name);
    if (!path) return INVALID_HANDLE_VALUE;
    HANDLE handle = local_handle_wide(path, access, disposition, security, directory);
    free(path);
    return handle;
}

static BOOL valid_component(const char *name, size_t size) {
    if (!size || size > 255 || name[size-1] == ' ' || name[size-1] == '.') return FALSE;
    for (size_t i = 0; i < size; ++i) {
        unsigned char x = (unsigned char)name[i];
        if (x < 32 || x == ':' || x == '/' || x == '\\' || x == '*' || x == '?' ||
            x == '"' || x == '<' || x == '>' || x == '|') return FALSE;
    }
    return TRUE;
}

static HANDLE open_relative(HANDLE dir, const char *name, ACCESS_MASK access, ULONG disposition,
                            int directory) {
    if (!dir || dir == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    if (!strcmp(name, ".") && directory != 0 && disposition == FILE_OPEN) {
        HANDLE duplicate;
        return DuplicateHandle(GetCurrentProcess(), dir, GetCurrentProcess(), &duplicate, 0,
                               FALSE, DUPLICATE_SAME_ACCESS) ? duplicate : INVALID_HANDLE_VALUE;
    }
    if (!valid_component(name, strlen(name))) return INVALID_HANDLE_VALUE;
    wchar_t *wide = eco_wide(name);
    if (!wide) return INVALID_HANDLE_VALUE;
    size_t bytes = wcslen(wide) * sizeof(*wide);
    UNICODE_STRING text = {.Length = (USHORT)bytes, .MaximumLength = (USHORT)bytes, .Buffer = wide};
    OBJECT_ATTRIBUTES object = {.Length = sizeof(object), .RootDirectory = dir, .ObjectName = &text,
                                .Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE};
    IO_STATUS_BLOCK io;
    HANDLE value = INVALID_HANDLE_VALUE;
    ULONG options = FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT;
    if (directory == 1) options |= FILE_DIRECTORY_FILE;
    if (directory == 0) options |= FILE_NON_DIRECTORY_FILE;
    NtCreateFileFn create = nt_create();
    // valid_handle reads the attributes, so every handle needs FILE_READ_ATTRIBUTES.
    NTSTATUS status = create ? create(&value, access | SYNCHRONIZE | FILE_READ_ATTRIBUTES, &object, &io, NULL,
                                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                      disposition, options, NULL, 0) : -1;
    free(wide);
    if (status < 0) return INVALID_HANDLE_VALUE;
    return valid_handle(value, directory);
}

static HANDLE file_at(int dir, const char *name, ACCESS_MASK access, ULONG disposition, int directory) {
    EcoDescriptor *entry = eco_descriptor(dir);
    if (!entry || entry->type != EC_FILE) return INVALID_HANDLE_VALUE;
    return open_relative(entry->input, name, access, disposition, directory);
}

#define DIRECTORY_ACCESS (FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL)

int eco_root(const char *name) {
    return eco_file_handle(local_handle(name, DIRECTORY_ACCESS, OPEN_EXISTING, NULL, 1));
}

int eco_parent(int root, const char *path, char *leaf, int capacity) {
    HANDLE dir = file_at(root, ".", DIRECTORY_ACCESS, FILE_OPEN, 1);
    if (dir == INVALID_HANDLE_VALUE) return -1;
    const char *part = path;
    while (1) {
        size_t length = strcspn(part, "/\\");
        BOOL self = part == path && length == 1 && part[0] == '.' && part[1] == 0;
        if ((!self && !valid_component(part, length)) || length >= (size_t)capacity) break;
        memcpy(leaf, part, length);
        leaf[length] = 0;
        if (!part[length]) return eco_file_handle(dir);
        HANDLE next = open_relative(dir, leaf, DIRECTORY_ACCESS, FILE_OPEN, 1);
        CloseHandle(dir);
        if (next == INVALID_HANDLE_VALUE) return -1;
        dir = next;
        part += length + 1;
    }
    CloseHandle(dir);
    return -1;
}

int eco_open(int dir, const char *leaf, int want_dir) {
    return eco_file_handle(file_at(dir, leaf, want_dir ? DIRECTORY_ACCESS : FILE_GENERIC_READ, FILE_OPEN,
                                   want_dir != 0));
}

int eco_stat(int dir, const char *leaf, uint64_t *size, uint8_t *kind, uint64_t *stamp) {
    HANDLE file = file_at(dir, leaf, FILE_READ_ATTRIBUTES, FILE_OPEN, -1);
    if (file == INVALID_HANDLE_VALUE) return -1;
    FILE_STANDARD_INFO std;
    FILE_BASIC_INFO basic;
    BOOL ok = GetFileInformationByHandleEx(file, FileStandardInfo, &std, sizeof(std)) &&
              GetFileInformationByHandleEx(file, FileBasicInfo, &basic, sizeof(basic));
    CloseHandle(file);
    if (!ok) return -1;
    *size = std.Directory ? 0 : (uint64_t)std.EndOfFile.QuadPart;
    *kind = std.Directory ? 2 : 1;
    const int64_t epoch = INT64_C(116444736000000000);
    *stamp = basic.LastWriteTime.QuadPart > epoch
        ? (uint64_t)(basic.LastWriteTime.QuadPart - epoch) * 100 : 0;
    return 0;
}

typedef struct EcoDirectory {
    int fd;
    size_t offset;
    BOOL restart, fetch;
    union {
        FILE_ID_BOTH_DIR_INFO align;
        unsigned char bytes[8192];
    } buffer;
} EcoDirectory;

void *eco_directory(int fd) {
    if (!eco_descriptor(fd)) return NULL;
    EcoDirectory *directory = calloc(1, sizeof(*directory));
    if (directory) {
        directory->fd = fd;
        directory->fetch = directory->restart = TRUE;
    }
    return directory;
}

void eco_dir_close(void *handle) {
    EcoDirectory *directory = handle;
    eco_close(directory->fd);
    free(directory);
}

int eco_dir_next(void *handle, char *out, int capacity) {
    EcoDirectory *dir = handle;
    EcoDescriptor *entry = eco_descriptor(dir->fd);
    if (!entry) return -1;
    for (;;) {
        if (dir->fetch) {
            FILE_INFO_BY_HANDLE_CLASS info = dir->restart ? FileIdBothDirectoryRestartInfo : FileIdBothDirectoryInfo;
            if (!GetFileInformationByHandleEx(entry->input, info, dir->buffer.bytes, sizeof(dir->buffer))) {
                DWORD error = GetLastError();
                return error == ERROR_NO_MORE_FILES || error == ERROR_FILE_NOT_FOUND ? 0 : -1;
            }
            dir->restart = dir->fetch = FALSE;
            dir->offset = 0;
        }
        const size_t header = offsetof(FILE_ID_BOTH_DIR_INFO, FileName);
        if (dir->offset > sizeof(dir->buffer.bytes) - header) return -1;
        FILE_ID_BOTH_DIR_INFO *record = (void *)(dir->buffer.bytes + dir->offset);
        if (record->FileNameLength > sizeof(dir->buffer.bytes) - dir->offset - header ||
            record->FileNameLength % sizeof(wchar_t)) return -1;
        int length = (int)(record->FileNameLength / sizeof(wchar_t));
        if (record->NextEntryOffset && (record->NextEntryOffset < header ||
            record->NextEntryOffset > sizeof(dir->buffer.bytes) - dir->offset)) return -1;
        dir->fetch = !record->NextEntryOffset;
        dir->offset += record->NextEntryOffset;
        if ((length == 1 && record->FileName[0] == L'.') ||
            (length == 2 && record->FileName[0] == L'.' && record->FileName[1] == L'.')) continue;
        int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, record->FileName, length,
                                        out, capacity, NULL, NULL);
        return bytes ? bytes : -1;
    }
}

int eco_file_create(int dir, const char *name) {
    return eco_file_handle(file_at(dir, name, FILE_GENERIC_WRITE, FILE_CREATE, 0));
}

typedef struct EcoRename {
    BOOLEAN replace;
    HANDLE root;
    ULONG bytes;
    wchar_t name[1];
} EcoRename;

int eco_rename(int dir, const char *from, const char *to) {
    EcoDescriptor *parent = eco_descriptor(dir);
    if (!parent || !valid_component(to, strlen(to))) return -1;
    HANDLE file = file_at(dir, from, DELETE | FILE_READ_ATTRIBUTES, FILE_OPEN, 0);
    if (file == INVALID_HANDLE_VALUE) return -1;
    wchar_t *wide = eco_wide(to);
    size_t bytes = wide ? wcslen(wide) * sizeof(*wide) : 0;
    size_t total = offsetof(EcoRename, name) + bytes;
    EcoRename *rename = wide ? calloc(1, total) : NULL;
    int result = -1;
    NtSetInformationFileFn set_file = nt_set();
    if (rename && set_file) {
        rename->replace = TRUE;
        rename->root = parent->input;
        rename->bytes = (ULONG)bytes;
        memcpy(rename->name, wide, bytes);
        IO_STATUS_BLOCK io;
        // FileRenameInformation accepts a name relative to the directory handle.
        if (set_file(file, &io, rename, (ULONG)total, (FILE_INFORMATION_CLASS)10) >= 0) result = 0;
    }
    free(rename);
    free(wide);
    CloseHandle(file);
    return result;
}

int eco_remove(int dir, const char *name) {
    HANDLE file = file_at(dir, name, DELETE | FILE_READ_ATTRIBUTES, FILE_OPEN, 0);
    if (file == INVALID_HANDLE_VALUE) return -1;
    FILE_DISPOSITION_INFO remove = {.DeleteFile = TRUE};
    BOOL ok = SetFileInformationByHandle(file, FileDispositionInfo, &remove, sizeof(remove));
    CloseHandle(file);
    return ok ? 0 : -1;
}

int eco_sync(int fd) {
    EcoDescriptor *entry = eco_descriptor(fd);
    return entry && FlushFileBuffers(entry->input) ? 0 : -1;
}

int eco_check_private_dir(const char *name) {
    HANDLE file = local_handle(name, DIRECTORY_ACCESS, OPEN_EXISTING, NULL, 1);
    if (file == INVALID_HANDLE_VALUE) return 0;
    BOOL ok = eco_private_owner(file, TRUE);
    CloseHandle(file);
    return ok;
}

int eco_lock_local(const char *name) {
    wchar_t *wide = eco_wide(name);
    if (!wide) return -1;
    SECURITY_ATTRIBUTES security;
    PSECURITY_DESCRIPTOR descriptor;
    if (eco_pipe_security(&security, &descriptor) < 0) { free(wide); return -1; }
    HANDLE file = valid_handle(CreateFileW(wide, GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                                0, &security, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, NULL), 0);
    LocalFree(descriptor);
    free(wide);
    if (file == INVALID_HANDLE_VALUE) return -1;
    if (!eco_private_owner(file, TRUE)) { CloseHandle(file); return -1; }
    return eco_file_handle(file);
}

int eco_safe_private_file(const char *name) {
    HANDLE file = local_handle(name, GENERIC_READ | READ_CONTROL, OPEN_EXISTING, NULL, 0);
    if (file == INVALID_HANDLE_VALUE) return -1;
    LARGE_INTEGER length;
    if (!eco_private_owner(file, TRUE) || !GetFileSizeEx(file, &length) || length.QuadPart != 32) {
        CloseHandle(file);
        return -1;
    }
    return eco_file_handle(file);
}

int eco_make_private(const char *name, const void *buffer, int length) {
    SECURITY_ATTRIBUTES security;
    PSECURITY_DESCRIPTOR descriptor;
    if (eco_pipe_security(&security, &descriptor) < 0) return -1;
    HANDLE file = local_handle(name, GENERIC_WRITE | DELETE, CREATE_NEW, &security, 0);
    LocalFree(descriptor);
    if (file == INVALID_HANDLE_VALUE) return -1;
    DWORD written = 0;
    BOOL ok = WriteFile(file, buffer, (DWORD)length, &written, NULL) &&
              written == (DWORD)length && FlushFileBuffers(file);
    if (!ok) {
        FILE_DISPOSITION_INFO remove = {.DeleteFile = TRUE};
        SetFileInformationByHandle(file, FileDispositionInfo, &remove, sizeof(remove));
    }
    CloseHandle(file);
    return ok ? 0 : -1;
}

int eco_install_file(const char *part, const char *final) {
    wchar_t *link = eco_wide(final);
    wchar_t *source = eco_wide(part);
    BOOL ok = link && source && CreateHardLinkW(link, source, NULL);
    DWORD error = GetLastError();
    free(link);
    free(source);
    return ok ? 0 : error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS ? 1 : -1;
}

int eco_sync_dir(const char *path) {
    // Windows has no unprivileged directory fsync. The file was flushed before publication.
    return eco_check_private_dir(path) ? 0 : -1;
}

static BOOL same_directory(HANDLE directory, const wchar_t *path) {
    HANDLE ordinary = local_handle_wide(path, FILE_READ_ATTRIBUTES, OPEN_EXISTING, NULL, 1);
    if (ordinary == INVALID_HANDLE_VALUE) return FALSE;
    FILE_ID_INFO original_id, ordinary_id;
    BOOL same = GetFileInformationByHandleEx(directory, FileIdInfo, &original_id, sizeof(original_id)) &&
                GetFileInformationByHandleEx(ordinary, FileIdInfo, &ordinary_id, sizeof(ordinary_id)) &&
                original_id.VolumeSerialNumber == ordinary_id.VolumeSerialNumber &&
                !memcmp(&original_id.FileId, &ordinary_id.FileId, sizeof(original_id.FileId));
    CloseHandle(ordinary);
    return same;
}

wchar_t *eco_working_directory(HANDLE handle) {
    const size_t prefix_length = 4;
    DWORD length = GetFinalPathNameByHandleW(handle, NULL, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!length || length >= 32767) return NULL;
    wchar_t *path = malloc((size_t)length * sizeof(*path));
    if (!path) return NULL;
    DWORD used = GetFinalPathNameByHandleW(handle, path, length, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!used || used >= length) { free(path); return NULL; }
    // Some shells reject the extended spelling of a drive path as their current directory.
    if (used >= prefix_length + 3 && used - prefix_length < MAX_PATH &&
        wcsncmp(path, L"\\\\?\\", prefix_length) == 0) {
        const wchar_t *ordinary = path + prefix_length;
        if (ordinary[1] == L':' && ordinary[2] == L'\\' && same_directory(handle, ordinary))
            memmove(path, ordinary, (used - prefix_length + 1) * sizeof(*path));
    }
    return path;
}
