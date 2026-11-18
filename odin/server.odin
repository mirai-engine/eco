package eco

import "core:c"
import "core:crypto/ecdh"
import "core:encoding/hex"
import "core:net"
import "core:os"
import "core:strings"
import "core:time"
import "deps:blake3"

Op :: enum u8 {
    Ping = 1, Stat, List, Read, Write, Hash, Watch, Run, Tty, Tcp, Udp, Start, Attach, Jobs, Kill,
    Upload = 16, Commit, Cancel, Touch, Input, Input_End, Resize, Session,
    Stdout = 32, Stderr, Entry, Info, Digest, Done, Failure, Ready, Output_End,
}

Access :: enum { Read, Write, Run, Tunnel }

Server :: struct {
    udp: net.UDP_Socket,
    own: ecdh.Private_Key,
    peer: ecdh.Public_Key,
    access: Access,
    policy: Policy,
    root: c.int,
    root_path, jobs: string,
    links: [16]^Link,
    rate_at: time.Tick,
    handshakes: int,
}

Server_Call :: struct {
    op: Op,
    file, parent, pid: c.int,
    output: [2]c.int,
    input: c.int,
    input_used, input_offset: int,
    input_pending: [MESSAGE_MAX-1]byte,
    directory: rawptr,
    leaf, temp: [256]byte,
    hashing: blake3.Hasher,
    done, committed, connecting, input_end, output_end: bool,
    deadline, poll_at, exited_at: time.Tick,
    size, stamp: u64,
    kind: u8,
    exit_code: c.int,
    job_path: string,
    job_output: [2]^os.File,
}

CALL_QUEUE :: 8

reply :: proc(stream: ^Stream, op: Op, body: []byte = nil) {
    _ = send_message(stream, u8(op), body)
}

finish_call :: proc(stream: ^Stream, call: ^Server_Call, code: c.int) {
    value: [4]byte
    put_u32(value[:], u32(code))
    reply(stream, .Done, value[:])
    call.done = true
}

fail_call :: proc(stream: ^Stream, call: ^Server_Call, message: string) {
    reply(stream, .Failure, transmute([]byte)message)
    call.done = true
}

close_fd :: proc(fd: ^c.int) {
    if fd^ >= 0 {
        _ = eco_close(fd^)
        fd^ = -1
    }
}

dispose_call :: proc(call: ^Server_Call) {
    if call == nil { return }
    if call.pid > 0 { eco_child_kill(call.pid) }
    if call.directory != nil { eco_dir_close(call.directory) }
    for file in call.job_output { if file != nil { _ = os.close(file) } }
    if call.job_path != "" { delete(call.job_path) }
    close_fd(&call.input)
    close_fd(&call.output[0])
    close_fd(&call.output[1])
    close_fd(&call.file)
    if call.parent >= 0 && call.temp[0] != 0 && !call.committed {
        _ = eco_remove(call.parent, cstring(&call.temp[0]))
    }
    close_fd(&call.parent)
    free(call)
}

close_server_stream :: proc(slot: ^^Stream) {
    dispose_call(cast(^Server_Call)slot^.application)
    free_stream(slot)
}

close_link :: proc(slot: ^^Link) {
    for &stream in slot^.streams {
        if stream != nil { close_server_stream(&stream) }
    }
    close_fd(&slot^.scope)
    free_link(slot)
}

free_link :: proc(slot: ^^Link) {
    reset_link(slot^)
    free(slot^)
    slot^ = nil
}

parent_for :: proc(root: c.int, path: []byte, leaf: ^[256]byte) -> c.int {
    if len(path) == 0 || len(path) >= MESSAGE_MAX || strings.index_byte(string(path), 0) >= 0 {
        return -1
    }
    name: [MESSAGE_MAX]byte
    copy(name[:], path)
    return eco_parent(root, cstring(&name[0]), raw_data(leaf[:]), c.int(len(leaf)))
}

stat_call :: proc(stream: ^Stream, call: ^Server_Call, first: bool) -> bool {
    size, stamp: u64
    kind: u8
    exists := eco_stat(call.parent, cstring(&call.leaf[0]), &size, &kind, &stamp) == 0
    if !exists && first {
        fail_call(stream, call, "path does not exist or cannot be inspected")
        return false
    }
    if first || size != call.size || stamp != call.stamp || kind != call.kind {
        call.size, call.stamp, call.kind = size, stamp, kind
        data: [17]byte
        data[0] = kind
        put_u64(data[1:], size)
        put_u64(data[9:], stamp)
        reply(stream, .Info, data[:])
    }
    return true
}

start_process :: proc(root: c.int, call: ^Server_Call, data: []byte, confined := false) -> string {
    if len(data) < 13 || data[len(data)-1] != 0 {
        return "invalid run arguments"
    }
    timeout := get_u32(data)
    flags := data[4]
    rows := u16(data[5]) | u16(data[6]) << 8
    cols := u16(data[7]) | u16(data[8]) << 8
    tty := call.op == .Tty
    if flags > 1 || (tty && (rows == 0 || cols == 0 || flags != 1)) {
        return "invalid terminal options"
    }
    body := data[9:]
    cwd_end := strings.index_byte(string(body), 0)
    if timeout == 0 || timeout > 24*60*60*1000 || cwd_end <= 0 || cwd_end == len(body)-1 {
        return "invalid work directory or timeout"
    }

    parent := parent_for(root, body[:cwd_end], &call.leaf)
    if parent < 0 {
        return "invalid work directory"
    }
    defer _ = eco_close(parent)
    dir := eco_open(parent, cstring(&call.leaf[0]), 1)
    if dir < 0 {
        return "cannot open work directory"
    }
    defer _ = eco_close(dir)

    args: [65]cstring
    // NUL termini are already present in the wire buffer.
    offset := cwd_end+1
    count := 0
    for offset < len(body) {
        if count == len(args)-1 || (count == 0 && body[offset] == 0) {
            return "invalid executable or too many arguments"
        }
        args[count] = cstring(&body[offset])
        count += 1
        offset += strings.index_byte(string(body[offset:]), 0)+1
    }
    scope := root if confined else -1
    if confined && eco_scope_supported() != 1 { return "OS cannot enforce the execution scope" }
    if tty {
        call.pid = eco_spawn_pty(raw_data(args[:]), &call.output[0], dir, rows, cols, scope)
    } else {
        input := &call.input if flags == 1 else nil
        call.pid = eco_spawn(raw_data(args[:]), raw_data(call.output[:]), dir, input, scope)
    }
    if call.pid < 0 {
        return "cannot start executable"
    }
    call.deadline = time.tick_add(time.tick_now(), time.Duration(timeout)*time.Millisecond)
    return ""
}

open_run :: proc(stream: ^Stream, call: ^Server_Call, body: []byte) {
    if error := start_process(stream.link.scope, call, body, stream.link.confined); error != "" {
        fail_call(stream, call, error)
    }
}

open_call :: proc(server: ^Server, stream: ^Stream, call: ^Server_Call, message: []byte) {
    call.op = Op(message[0])
    stream.bulk = call.op == .Read || call.op == .Write
    body := message[1:]
    if call.op == .Ping {
        if len(body) != 0 { fail_call(stream, call, "invalid ping"); return }
        finish_call(stream, call, 0)
        return
    }
    if call.op >= .Start && call.op <= .Kill {
        if server.access != .Run || stream.link.rights & CAP_RUN == 0 ||
           (stream.link.confined && eco_scope_supported() != 1) || server.jobs == "" {
            fail_call(stream, call, "persistent jobs are disabled")
            return
        }
        open_job(server, stream, call, body)
        return
    }
    if call.op == .Tcp || call.op == .Udp {
        if (server.access != .Run && server.access != .Tunnel) || stream.link.rights & CAP_TUNNEL == 0 {
            fail_call(stream, call, "forwarding is disabled")
            return
        }
        open_tunnel(stream, call, body)
        return
    }
    if call.op == .Run || call.op == .Tty {
        if server.access != .Run || stream.link.rights & CAP_RUN == 0 { fail_call(stream, call, "execution is disabled"); return }
        open_run(stream, call, body)
        return
    }
    if call.op < .Stat || call.op > .Watch {
        fail_call(stream, call, "unsupported request")
        return
    }
    if call.op == .Write && ((server.access != .Write && server.access != .Run) || stream.link.rights & CAP_WRITE == 0) {
        fail_call(stream, call, "writes are disabled")
        return
    }

    if call.op != .Write && stream.link.rights & CAP_READ == 0 {
        fail_call(stream, call, "reads are disabled")
        return
    }
    call.parent = parent_for(stream.link.scope, body, &call.leaf)
    if call.parent < 0 { fail_call(stream, call, "invalid or inaccessible path"); return }
    leaf := cstring(&call.leaf[0])
    #partial switch call.op {
    case .Stat, .Watch:
        if stat_call(stream, call, true) && call.op == .Stat { finish_call(stream, call, 0) }
    case .List:
        dir := eco_open(call.parent, leaf, 1)
        if dir >= 0 {
            call.directory = eco_directory(dir)
            if call.directory == nil { _ = eco_close(dir) }
        }
        if call.directory == nil { fail_call(stream, call, "cannot open directory") }
    case .Read, .Hash:
        call.file = eco_open(call.parent, leaf, 0)
        if call.file < 0 { fail_call(stream, call, "cannot open regular file"); return }
        blake3.init(&call.hashing)
    case .Write:
        ticket: [16]byte
        random_bytes(ticket[:])
        copy(call.temp[:], ".eco-part-")
        name := hex.encode(ticket[:])
        copy(call.temp[10:], name)
        delete(name)
        call.file = eco_file_create(call.parent, cstring(&call.temp[0]))
        if call.file < 0 {
            call.temp[0] = 0
            fail_call(stream, call, "cannot create temporary file")
            return
        }
        blake3.init(&call.hashing)
        reply(stream, .Ready)
    }
}

write_fd :: proc(fd: c.int, data: []byte) -> bool {
    left := data
    for len(left) > 0 {
        n := eco_write(fd, raw_data(left), c.int(len(left)))
        if n <= 0 { return false }
        left = left[n:]
    }
    return true
}

receive_call :: proc(stream: ^Stream, call: ^Server_Call, message: []byte) {
    op := Op(message[0])
    body := message[1:]
    if op == .Touch && len(body) == 0 { return }
    if op == .Cancel && len(body) == 0 {
        finish_call(stream, call, 130)
        return
    }
    if call.op == .Tcp || call.op == .Udp {
        if op == .Input && !call.input_end && (len(body) > 0 || call.op == .Udp) {
            call.input_used = copy(call.input_pending[:], body)
            call.input_offset = 0
            if len(body) == 0 && eco_write(call.file, raw_data(body), 0) != 0 {
                fail_call(stream, call, "cannot forward empty datagram")
            }
        } else if op == .Input_End && len(body) == 0 && call.op == .Tcp {
            _ = eco_net_fin(call.file)
            call.input_end = true
        } else {
            fail_call(stream, call, "unexpected tunnel message")
        }
        return
    }
    if call.op == .Run || call.op == .Tty {
        tty := call.op == .Tty
        if op == .Input && len(body) > 0 {
            if call.input >= 0 || (tty && call.output[0] >= 0) {
                call.input_used = copy(call.input_pending[:], body)
                call.input_offset = 0
            }
            return
        }
        if op == .Input_End && len(body) == 0 && !tty {
            close_fd(&call.input)
            return
        }
        if op == .Resize && len(body) == 4 && tty && call.output[0] >= 0 {
            rows := u16(body[0]) | u16(body[1]) << 8
            cols := u16(body[2]) | u16(body[3]) << 8
            if rows > 0 && cols > 0 { _ = eco_terminal_resize(call.output[0], rows, cols) }
            return
        }
    }
    if call.op != .Write {
        fail_call(stream, call, "unexpected request data")
        return
    }
    #partial switch op {
    case .Upload:
        if len(body) == 0 || !write_fd(call.file, body) {
            fail_call(stream, call, "failed to write file")
            return
        }
        blake3.update(&call.hashing, body)
    case .Commit:
        digest := blake3.final(&call.hashing)
        if len(body) != len(digest) || string(body) != string(digest[:]) {
            fail_call(stream, call, "BLAKE3 verification failed")
            return
        }
        if eco_sync(call.file) < 0 || eco_rename(call.parent, cstring(&call.temp[0]), cstring(&call.leaf[0])) < 0 {
            fail_call(stream, call, "cannot replace file")
            return
        }
        call.committed = true
        finish_call(stream, call, 0)
    case:
        fail_call(stream, call, "unexpected upload message")
    }
}

pump_run :: proc(stream: ^Stream, call: ^Server_Call, buffer: []byte) -> bool {
    now := time.tick_now()
    progressed := false
    for &fd, i in call.output {
        if fd < 0 { continue }
        n := eco_read(fd, raw_data(buffer), c.int(len(buffer)))
        if n == 0 {
            close_fd(&fd)
        } else if n > 0 {
            reply(stream, .Stdout if i == 0 else .Stderr, buffer[:n])
            progressed = true
        } else if n != -2 && call.op == .Tty {
            close_fd(&fd)
        } else if n != -2 {
            fail_call(stream, call, "failed to read child output")
            return false
        }
    }
    if call.pid > 0 {
        result := eco_child_poll(call.pid, &call.exit_code)
        if result < 0 {
            call.pid = -1
            fail_call(stream, call, "cannot reap process")
            return false
        }
        if result > 0 {
            call.pid = -1
            call.exited_at = now
        }
    }
    if call.pid < 0 && (call.output == {-1, -1} || (!progressed && time.tick_since(call.exited_at) > 100*time.Millisecond) ||
                        time.tick_since(call.exited_at) > time.Second) {
        finish_call(stream, call, call.exit_code)
    }
    return progressed
}

pump_call :: proc(stream: ^Stream, call: ^Server_Call, buffer: []byte) -> bool {
    #partial switch call.op {
    case .Attach:
        return pump_job(stream, call, buffer)
    case .Jobs:
        return pump_job_list(stream, call, buffer)
    case .Read, .Hash:
        n := eco_read(call.file, raw_data(buffer), c.int(len(buffer)))
        if n < 0 { fail_call(stream, call, "failed to read file"); return false }
        if n == 0 {
            digest := blake3.final(&call.hashing)
            reply(stream, .Digest, digest[:])
            finish_call(stream, call, 0)
            return false
        }
        blake3.update(&call.hashing, buffer[:n])
        if call.op == .Read { reply(stream, .Stdout, buffer[:n]) }
        return true
    case .List:
        n := eco_dir_next(call.directory, raw_data(buffer), c.int(len(buffer)))
        if n < 0 { fail_call(stream, call, "failed to read directory"); return false }
        if n == 0 { finish_call(stream, call, 0); return false }
        reply(stream, .Entry, buffer[:n])
        return true
    case .Watch:
        if call.poll_at == {} || time.tick_since(call.poll_at) >= 250*time.Millisecond {
            _ = stat_call(stream, call, false)
            call.poll_at = time.tick_now()
        }
    case .Run, .Tty:
        return pump_run(stream, call, buffer)
    case .Tcp, .Udp:
        return pump_tunnel(stream, call, buffer)
    }
    return false
}

process_stream :: proc(server: ^Server, slot: ^^Stream) -> bool {
    stream := slot^
    if time.tick_since(stream.last_seen) >= ACTIVE_TIMEOUT {
        close_server_stream(slot)
        return false
    }
    buffer: [MESSAGE_MAX]byte
    call := cast(^Server_Call)stream.application
    if call == nil && !stream.finished {
        message := read_message(stream, buffer[:])
        if message != nil {
            call = new(Server_Call)
            call.file, call.parent, call.pid = -1, -1, -1
            call.output = {-1, -1}
            call.input = -1
            stream.application = call
            open_call(server, stream, call, message)
        }
    }

    progressed := false
    if call != nil {
        if (call.op == .Run || call.op == .Tty) && !call.done &&
           call.pid > 0 && time.tick_since(call.deadline) >= 0 {
            eco_child_kill(call.pid)
            call.pid = -1
            fail_call(stream, call, "execution timed out")
        }
        for i in 0..<window_for(stream) {
            if call.done { break }
            if call.input_offset < call.input_used {
                if !pump_input(call) { break }
            }
            message := read_message(stream, buffer[:])
            if message == nil { break }
            receive_call(stream, call, message)
        }
        for i in 0..<window_for(stream) {
            if call.done || ikcp_waitsnd(stream.kcp) >= c.int(window_for(stream)) { break }
            if !pump_call(stream, call, buffer[:MESSAGE_MAX-1]) { break }
            progressed = true
        }
        if call.done {
            // Release filesystem handles and kill a canceled child without waiting for delivery.
            dispose_call(call)
            stream.application = nil
            stream.finished = true
        }
    }
    flush_stream(stream)
    if stream.finished && ikcp_waitsnd(stream.kcp) == 0 { close_server_stream(slot) }
    return progressed
}

receive_server :: proc(server: ^Server, packet, scratch: []byte, from: net.Endpoint) {
    header, ok := parse_header(packet)
    if !ok { return }
    for link in server.links {
        if link == nil || link.id != header.id { continue }
        if header.kind == .Hello {
            if !link.verified && same_endpoint(from, link.remote) &&
               string(link.client_hello[:link.hello_len]) == string(packet) {
                _, _ = net.send_udp(server.udp, link.server_hello[:link.welcome_len], from)
            }
        } else {
            if link.closing || time.tick_since(link.born) >= SESSION_LIFETIME ||
               (link.grant_expiry != 0 && u64(time.to_unix_seconds(time.now())) >= link.grant_expiry) {
                return
            }
            if query := receive_record(link, header, from, packet, scratch, true); query != nil {
                answer_query(link, query)
            }
        }
        return
    }
    if header.kind != .Hello || len(packet) < HELLO_MIN || len(packet) > HELLO_MAX { return }
    if server.rate_at == {} || time.tick_since(server.rate_at) >= time.Second {
        server.rate_at = time.tick_now()
        server.handshakes = 0
    }
    if server.handshakes >= 128 { return }
    for &slot in server.links {
        if slot != nil { continue }
        server.handshakes += 1
        slot = accept_link(server.udp, from, packet, header, &server.own, &server.peer, server.root, &server.policy)
        return
    }
}

serve :: proc(endpoint: net.Endpoint, own: ^ecdh.Private_Key, peer: ^ecdh.Public_Key,
              root: string, access: Access, policy: Policy, jobs: string) -> int {
    root_c := strings.clone_to_cstring(root)
    defer delete(root_c)
    fd := eco_root(root_c)
    if fd < 0 { return error_exit("cannot open the server root") }
    defer _ = eco_close(fd)
    udp, err := net.make_bound_udp_socket(endpoint.address, endpoint.port)
    if err != nil { return error_exit("cannot listen on UDP", err) }
    udp_fd := eco_socket_fd(uintptr(udp))
    if udp_fd < 0 { net.close(udp); return error_exit("cannot register UDP socket") }
    defer _ = eco_close(udp_fd)
    if eco_fd_setup(udp_fd, 1) < 0 { return error_exit("cannot configure UDP socket") }
    server := Server{udp = udp, own = own^, peer = peer^, root = fd, access = access, policy = policy, root_path = root, jobs = jobs}
    bulk: Bulk_Server
    if bulk_enabled() && !enable_bulk(endpoint, &bulk) { return error_exit("cannot listen for bulk TCP") }
    defer clear_bulk(&bulk)
    defer ecdh.private_key_clear(&server.own)
    defer for &link in server.links { if link != nil { close_link(&link) } }

    children := eco_child_events()
    if children < 0 { return error_exit("cannot subscribe to child exit") }
    defer _ = eco_close(children)
    eco_listening(c.int(endpoint.port))
    if ODIN_OS == .Linux && eco_ring_setup() == 1 { eco_ring_ready() }
    defer eco_ring_close()
    buffer: [MAX_PACKET+1]byte
    scratch: [KCP_MTU]byte
    for eco_stopping() == 0 {
        for eco_read(children, raw_data(buffer[:]), c.int(len(buffer))) > 0 {}
        for _ in 0..<64 {
            n, from, read_err := net.recv_udp(udp, buffer[:])
            if read_err != nil { break }
            receive_server(&server, buffer[:n], scratch[:], from)
        }
        timeout: c.int = 1000
        fds, events: [66]c.int
        fds[0], events[0] = udp_fd, POLL_READ
        fds[1], events[1] = children, POLL_READ
        count := 2
        poll_bulk(&bulk, &server, fds[:], events[:], &count, &timeout)
        for &link in server.links {
            if link == nil { continue }
            if link.closing || (link.grant_expiry != 0 && u64(time.to_unix_seconds(time.now())) >= link.grant_expiry) ||
               time.tick_since(link.born) >= SESSION_LIFETIME || time.tick_since(link.seen) >= IDLE_LIFETIME ||
               (!link.verified && time.tick_since(link.born) >= 4*time.Second) {
                close_link(&link)
                continue
            }
            if drain_pacer(link) { timeout = min(timeout, 1) }
            for &stream in link.streams {
                if stream == nil { continue }
                progressed := process_stream(&server, &stream)
                timeout = min(timeout, 10)
                if progressed && stream != nil && ikcp_waitsnd(stream.kcp) < c.int(window_for(stream)) { timeout = 0 }
                if stream == nil || stream.application == nil || count+2 > len(fds) { continue }
                call := cast(^Server_Call)stream.application
                if call.op == .Tcp || call.op == .Udp {
                    mask: c.int
                    if !call.output_end && ikcp_waitsnd(stream.kcp) < c.int(window_for(stream)) { mask |= POLL_READ }
                    if call.connecting || call.input_offset < call.input_used { mask |= POLL_WRITE }
                    fds[count], events[count] = call.file, mask
                    count += 1
                }
                if (call.op == .Run || call.op == .Tty) && ikcp_waitsnd(stream.kcp) < c.int(window_for(stream)) {
                    for file in call.output {
                        if file >= 0 {
                            fds[count], events[count] = file, POLL_READ
                            count += 1
                        }
                    }
                }
            }
        }
        _ = eco_poll(raw_data(fds[:]), raw_data(events[:]), c.int(count), timeout)
    }
    return 0
}

// Keep at most one forwarded message pending at the OS pipe or PTY.
pump_input :: proc(call: ^Server_Call) -> bool {
    network := call.op == .Tcp || call.op == .Udp
    fd := call.file if network else (call.output[0] if call.op == .Tty else call.input)
    if fd < 0 {
        call.input_offset = call.input_used
        return true
    }
    data := call.input_pending[call.input_offset:call.input_used]
    n := eco_write(fd, raw_data(data), c.int(len(data)))
    if n > 0 { call.input_offset += int(n) }
    if n == -2 { return false }
    if n <= 0 {
        if network { call.input_end = true }
        else if call.op != .Tty { close_fd(&call.input) }
        call.input_offset = call.input_used
    }
    return call.input_offset == call.input_used
}
