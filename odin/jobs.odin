package eco

import "core:c"
import "core:crypto/ecdh"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"

foreign import platform "../.eco-deps/libeco_platform.a"

@(default_calling_convention="c")
foreign platform {
    eco_start_worker :: proc(args: [^]cstring) -> c.int ---
    eco_install_file :: proc(part, final: cstring) -> c.int ---
    eco_sync_dir :: proc(path: cstring) -> c.int ---
}

JOB_ID :: 16
JOB_HEADER :: JOB_ID
JOB_OUTPUT_MAX :: 64*1024*1024

ensure_job_namespace :: proc(server: ^Server) -> string {
    peer: [32]byte
    ecdh.public_key_bytes(&server.peer, peer[:])
    name := hex.encode(peer[:])
    defer delete(name)
    directory := fmt.aprintf("%s/%s", server.jobs, string(name))
    _ = os.mkdir(directory, {.Read_User, .Write_User, .Execute_User})
    cdir := strings.clone_to_cstring(directory)
    defer delete(cdir)
    if eco_check_private_dir(cdir) != 1 {
        delete(directory)
        return ""
    }
    return directory
}

job_file :: proc(path, part: string) -> string {
    return fmt.aprintf("%s/%s", path, part)
}

launch_worker :: proc(path, root: string) -> bool {
    executable, err := os.get_executable_path(context.allocator)
    if err != nil { return false }
    defer delete(executable)
    arguments := []string{executable, "job-worker", path, root}
    args: [5]cstring
    defer for arg in args { if arg != nil { delete(arg) } }
    for arg, i in arguments { args[i] = strings.clone_to_cstring(arg) }
    return eco_start_worker(raw_data(args[:])) == 0
}

job_spec :: proc(path: string, spec: []byte) -> bool {
    cfg := job_file(path, "request")
    defer delete(cfg)
    if !os.exists(cfg) {
        tag: [8]byte
        random_bytes(tag[:])
        id := hex.encode(tag[:])
        defer delete(id)
        part := fmt.aprintf("%s/%s.part", path, string(id))
        defer delete(part)
        file, open_err := os.open(part, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
        if open_err != nil { return false }
        defer _ = os.remove(part)
        n, write_err := os.write(file, spec)
        sync_err := os.sync(file)
        close_err := os.close(file)
        if n != len(spec) || write_err != nil || sync_err != nil || close_err != nil { return false }
        part_c := strings.clone_to_cstring(part)
        cfg_c := strings.clone_to_cstring(cfg)
        dir_c := strings.clone_to_cstring(path)
        defer delete(part_c)
        defer delete(cfg_c)
        defer delete(dir_c)
        result := eco_install_file(part_c, cfg_c)
        if result < 0 { return false }
        if result == 0 { return eco_sync_dir(dir_c) == 0 }
    }
    existing, err := os.open(cfg)
    if err != nil { return false }
    defer _ = os.close(existing)
    data: [MESSAGE_MAX]byte
    n, read_err := os.read_at_least(existing, data[:], len(spec)+1)
    return (read_err == nil || read_err == .EOF || read_err == .Unexpected_EOF) &&
           n == len(spec) && string(data[:n]) == string(spec)
}

job_exists :: proc(path, part: string) -> bool {
    file := job_file(path, part)
    defer delete(file)
    return os.exists(file)
}

open_job :: proc(server: ^Server, stream: ^Stream, call: ^Server_Call, body: []byte) {
    namespace := ensure_job_namespace(server)
    if namespace == "" { fail_call(stream, call, "job store unavailable"); return }
    defer delete(namespace)

    if call.op == .Jobs && len(body) == 0 {
        name := strings.clone_to_cstring(namespace)
        defer delete(name)
        fd := eco_root(name)
        if fd >= 0 {
            call.directory = eco_directory(fd)
            if call.directory == nil { _ = eco_close(fd) }
        }
        if call.directory == nil { fail_call(stream, call, "cannot list jobs") }
        return
    }
    if len(body) < JOB_HEADER {
        fail_call(stream, call, "invalid job id")
        return
    }

    encoded := hex.encode(body[:JOB_ID])
    defer delete(encoded)
    call.job_path = job_file(namespace, string(encoded))
    body := body[JOB_HEADER:]

    #partial switch call.op {
    case .Start:
        if len(body) < 13 || body[4] != 0 {
            fail_call(stream, call, "background jobs require a command without stdin")
            return
        }
        _ = os.mkdir(call.job_path, {.Read_User, .Write_User, .Execute_User})
        if !job_spec(call.job_path, body) {
            fail_call(stream, call, "cannot save job or id already has different arguments")
            return
        }
        if !job_exists(call.job_path, "claimed") && !launch_worker(call.job_path, server.root_path) {
            fail_call(stream, call, "cannot start job worker; retry with the same id")
            return
        }
        reply(stream, .Entry, encoded)
        finish_call(stream, call, 0)
    case .Attach:
        if len(body) != 16 || !job_exists(call.job_path, "request") {
            fail_call(stream, call, "job does not exist")
            return
        }
        call.size, call.stamp = get_u64(body[:8]), get_u64(body[8:])
        if call.size > JOB_OUTPUT_MAX || call.stamp > JOB_OUTPUT_MAX {
            fail_call(stream, call, "job offset out of range")
        }
    case .Kill:
        if len(body) != 0 || !job_exists(call.job_path, "request") {
            fail_call(stream, call, "job does not exist")
            return
        }
        path := job_file(call.job_path, "cancel")
        defer delete(path)
        err := os.write_entire_file(path, "", {.Read_User, .Write_User})
        if err != nil { fail_call(stream, call, "cannot request job cancellation"); return }
        finish_call(stream, call, 0)
    case:
        fail_call(stream, call, "invalid job request")
    }
}

pump_job_list :: proc(stream: ^Stream, call: ^Server_Call, buffer: []byte) -> bool {
    n := eco_dir_next(call.directory, raw_data(buffer), c.int(len(buffer)))
    if n == 0 { finish_call(stream, call, 0); return false }
    if n < 0 { fail_call(stream, call, "cannot read job directory"); return false }
    id: [JOB_ID]byte
    if decode_key(string(buffer[:n]), id[:]) { reply(stream, .Entry, buffer[:n]) }
    return true
}

job_status :: proc(path: string) -> (c.int, bool) {
    status := job_file(path, "status")
    defer delete(status)
    file, err := os.open(status)
    if err != nil { return 0, false }
    defer _ = os.close(file)
    value: [4]byte
    n, result := os.read_full(file, value[:])
    return c.int(get_u32(value[:])), n == len(value) && result == nil
}

pump_job :: proc(stream: ^Stream, call: ^Server_Call, buffer: []byte) -> bool {
    // Read status before touching output so a published exit implies both files are complete.
    code, finished := job_status(call.job_path)
    progress := false
    for name, i in JOB_CHANNELS {
        if call.job_output[i] == nil {
            path := job_file(call.job_path, name)
            call.job_output[i], _ = os.open(path)
            delete(path)
            if call.job_output[i] == nil { continue }
        }
        offset := &call.size if i == 0 else &call.stamp
        n, err := os.read_at(call.job_output[i], buffer, i64(offset^))
        if err != nil && err != .EOF {
            fail_call(stream, call, "cannot read job output")
            return false
        }
        if n > 0 {
            offset^ += u64(n)
            reply(stream, .Stdout if i == 0 else .Stderr, buffer[:n])
            progress = true
        }
    }
    if finished && !progress { finish_call(stream, call, code) }
    if !finished && !progress && time.tick_since(stream.began) >= 2*time.Second &&
       (call.poll_at == {} || time.tick_since(call.poll_at) >= time.Second) {
        call.poll_at = time.tick_now()
        if !job_exists(call.job_path, "claimed") {
            fail_call(stream, call, "job worker has not claimed the request; retry start with the same id")
        } else {
            lock := worker_lock(call.job_path)
            if lock >= 0 {
                _ = eco_close(lock)
                if _, finished_now := job_status(call.job_path); !finished_now {
                    fail_call(stream, call, "job worker exited without status; result is unknown")
                }
            }
        }
    }
    return progress
}

JOB_CHANNELS :: [2]string{"stdout", "stderr"}

persist_job_status :: proc(path: string, code: c.int) -> bool {
    part := job_file(path, "status.part")
    final := job_file(path, "status")
    defer delete(part)
    defer delete(final)
    bytes: [4]byte
    put_u32(bytes[:], u32(code))
    file, err := os.open(part, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
    if err != nil { return false }
    n, write_err := os.write(file, bytes[:])
    sync_err := os.sync(file)
    close_err := os.close(file)
    return n == len(bytes) && write_err == nil && sync_err == nil && close_err == nil &&
           os.rename(part, final) == nil
}

worker_lock :: proc(path: string) -> c.int {
    lock := job_file(path, "worker.lock")
    defer delete(lock)
    name := strings.clone_to_cstring(lock)
    defer delete(name)
    return eco_lock_local(name)
}

job_worker :: proc(path, root: string) -> int {
    lock := worker_lock(path)
    if lock < 0 { return 125 }
    defer _ = eco_close(lock)
    children := eco_child_events()
    if children < 0 { return 125 }
    defer _ = eco_close(children)
    marker := job_file(path, "claimed")
    defer delete(marker)
    claim, err := os.open(marker, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
    if err != nil { return 0 }
    _ = os.close(claim)
    code: c.int = 125
    defer _ = persist_job_status(path, code)

    root_name := strings.clone_to_cstring(root)
    defer delete(root_name)
    fd := eco_root(root_name)
    if fd < 0 { return 125 }
    defer _ = eco_close(fd)
    request := job_file(path, "request")
    defer delete(request)
    file, spec_err := os.open(request)
    if spec_err != nil { return 125 }
    spec: [MESSAGE_MAX]byte
    n, read_err := os.read_at_least(file, spec[:], len(spec))
    _ = os.close(file)
    if n < 13 || n >= len(spec) || (read_err != nil && read_err != .Unexpected_EOF && read_err != .EOF) {
        return 125
    }

    call := Server_Call{file = -1, parent = -1, pid = -1, input = -1, output = {-1, -1}, op = .Run}
    defer {
        if call.pid > 0 { eco_child_kill(call.pid) }
        for &output in call.output { close_fd(&output) }
    }
    outputs: [2]^os.File
    defer for output in outputs { if output != nil { _ = os.sync(output); _ = os.close(output) } }
    for part, i in JOB_CHANNELS {
        name := job_file(path, part)
        output, open_err := os.open(name, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
        delete(name)
        if open_err != nil { return 125 }
        outputs[i] = output
    }
    if job_exists(path, "cancel") { code = 130; return int(code) }
    if explanation := start_process(fd, &call, spec[:n]); explanation != "" {
        _, _ = os.write_strings(outputs[1], explanation, "\n")
        return 125
    }

    bytes: [16*1024]byte
    counts: [2]int
    for {
        if eco_stopping() != 0 || job_exists(path, "cancel") { code = 130; return int(code) }
        if time.tick_since(call.deadline) >= 0 { code = 124; return int(code) }
        fds := [3]c.int{call.output[0], call.output[1], children}
        events := [3]c.int{POLL_READ, POLL_READ, POLL_READ}
        _ = eco_poll(raw_data(fds[:]), raw_data(events[:]), 3, 100)
        if events[2] & POLL_READ != 0 {
            for eco_read(children, raw_data(bytes[:]), c.int(len(bytes))) > 0 {}
        }
        for &source, i in call.output {
            if source < 0 { continue }
            data_len := eco_read(source, raw_data(bytes[:]), c.int(len(bytes)))
            if data_len == 0 { close_fd(&source); continue }
            if data_len == -2 { continue }
            if data_len < 0 || counts[i]+int(data_len) > JOB_OUTPUT_MAX {
                _, _ = os.write_string(outputs[1], "eco-odin: job output limit or read error\n")
                return 125
            }
            written, err := os.write(outputs[i], bytes[:data_len])
            if err != nil || written != int(data_len) { return 125 }
            counts[i] += int(data_len)
        }
        if call.pid > 0 {
            result := eco_child_poll(call.pid, &call.exit_code)
            if result < 0 { call.pid = -1; return 125 }
            if result > 0 {
                call.pid = -1
                call.exited_at = time.tick_now()
            }
        }
        if call.pid < 0 && (call.output == {-1, -1} || time.tick_since(call.exited_at) >= time.Second) {
            code = call.exit_code
            return int(code)
        }
    }
}
