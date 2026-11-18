package eco

import "core:c"
import "core:crypto/ecdh"
import "core:fmt"
import "core:net"
import "core:strings"
import "core:time"

foreign import platform "../.eco-deps/libeco_platform.a"

@(default_calling_convention="c")
foreign platform {
    eco_lock_local :: proc(name: cstring) -> c.int ---
    eco_check_private_dir :: proc(name: cstring) -> c.int ---
    eco_prepare_socket :: proc(name: cstring) -> c.int ---
    eco_safe_private_file :: proc(name: cstring) -> c.int ---
    eco_start_daemon :: proc(args: [^]cstring) -> c.int ---
}

Local_Call :: struct {
    fd: c.int,
    stream: ^Stream,
    input, output: [MESSAGE_MAX+2]byte,
    used, out_len, out_pos: int,
    complete, disconnecting: bool,
    last_touch, opened: time.Tick,
}

Bridge :: struct {
    endpoint: net.Endpoint,
    udp: net.UDP_Socket,
    link: ^Link,
    serial: u32,
    own: ^ecdh.Private_Key,
    peer: ^ecdh.Public_Key,
    calls: [STREAM_MAX]^Local_Call,
    idle, keepalive: time.Tick,
    token: []byte,
}

frame_local :: proc(packet: []byte, data: []byte) -> int {
    packet[0], packet[1] = byte(len(data)), byte(len(data) >> 8)
    copy(packet[2:], data)
    return 2+len(data)
}

local_size :: proc(packet: []byte) -> int {
    return int(packet[0]) | int(packet[1]) << 8
}

send_local :: proc(fd: c.int, op: Op, payload: []byte = nil) -> bool {
    if len(payload) >= MESSAGE_MAX { return false }
    packet: [MESSAGE_MAX+2]byte
    size := 1+len(payload)
    packet[0], packet[1], packet[2] = byte(size), byte(size >> 8), byte(op)
    copy(packet[3:], payload)
    return write_fd(fd, packet[:2+size])
}

read_fully :: proc(fd: c.int, buffer: []byte) -> bool {
    left := buffer
    for len(left) > 0 {
        size := eco_read(fd, raw_data(left), c.int(len(left)))
        if size <= 0 { return false }
        left = left[size:]
    }
    return true
}

read_local :: proc(fd: c.int, buffer: []byte) -> []byte {
    header: [2]byte
    if !read_fully(fd, header[:]) { return nil }
    size := local_size(header[:])
    if size == 0 || size > len(buffer) || !read_fully(fd, buffer[:size]) { return nil }
    return buffer[:size]
}

local_failure :: proc(call: ^Local_Call, message: string) {
    packet: [MESSAGE_MAX]byte
    packet[0] = byte(Op.Failure)
    copy(packet[1:], message)
    call.out_len = frame_local(call.output[:], packet[:1+len(message)])
    call.out_pos = 0
    call.complete = true
}

close_local :: proc(bridge: ^Bridge, slot: ^^Local_Call) {
    if slot^ == nil { return }
    call := slot^
    close_fd(&call.fd)
    if call.stream != nil && bridge.link != nil {
        for &stream in bridge.link.streams {
            if stream == call.stream {
                free_stream(&stream)
                break
            }
        }
    }
    free(call)
    slot^ = nil
}

connect_bridge :: proc(bridge: ^Bridge) -> bool {
    if bridge.link != nil { return true }
    link := new(Link)
    if !connect_link(bridge.udp, bridge.endpoint, bridge.own, bridge.peer, bridge.token, false, link) {
        free(link)
        return false
    }
    bridge.link = link
    bridge.keepalive = time.tick_now()
    bridge.serial = 0
    return true
}

read_call_input :: proc(call: ^Local_Call) -> ([]byte, bool) {
    needed := 2
    if call.used >= 2 {
        size := local_size(call.input[:2])
        if size <= 0 || size > MESSAGE_MAX { return nil, false }
        needed += size
    }
    if call.used == needed {
        call.used = 0
        return call.input[2:needed], true
    }
    n := eco_read(call.fd, &call.input[call.used], c.int(needed-call.used))
    if n <= 0 { return nil, n == -2 }
    call.used += int(n)
    if call.used == needed && needed > 2 {
        call.used = 0
        return call.input[2:needed], true
    }
    return nil, true
}

disconnect_local :: proc(call: ^Local_Call) {
    close_fd(&call.fd)
    if call.stream != nil && !call.complete && !call.disconnecting {
        reply(call.stream, .Cancel)
        flush_stream(call.stream)
        call.disconnecting = true
        call.opened = time.tick_now()
    }
}

forward_local :: proc(bridge: ^Bridge, call: ^Local_Call) -> bool {
    if call.out_pos < call.out_len && call.fd >= 0 {
        body := call.output[call.out_pos:call.out_len]
        n := eco_write(call.fd, raw_data(body), c.int(len(body)))
        if n > 0 { call.out_pos += int(n) }
        if n == 0 || n == -1 { disconnect_local(call) }
    }
    if call.complete && (call.out_pos == call.out_len || call.fd < 0) { return false }
    if call.disconnecting && time.tick_since(call.opened) >= 2*time.Second { return false }
    if call.stream == nil && time.tick_since(call.opened) >= 10*time.Second { return false }
    if call.fd >= 0 && !call.complete && (call.stream == nil || ikcp_waitsnd(call.stream.kcp) < CALL_QUEUE) {
        // Header and body may arrive separately, even for localhost writes.
        for _ in 0..<CALL_QUEUE {
            message, ok := read_call_input(call)
            if !ok { disconnect_local(call); break }
            if message == nil { break }
            if call.stream == nil {
                if !connect_bridge(bridge) {
                    local_failure(call, "cannot establish Noise session")
                    return true
                }
                bridge.serial += 1
                call.stream = new_stream(bridge.link, bridge.serial)
                if call.stream == nil {
                    local_failure(call, "no remote stream available")
                    return true
                }
            }
            if !send_message(call.stream, message[0], message[1:]) {
                local_failure(call, "cannot queue request")
                return true
            }
            if ikcp_waitsnd(call.stream.kcp) >= CALL_QUEUE { break }
        }
    }
    if call.stream == nil { return call.fd >= 0 }
    if !call.complete && !call.disconnecting && time.tick_since(call.last_touch) >= 10*time.Second &&
       ikcp_waitsnd(call.stream.kcp) < CALL_QUEUE {
        call.last_touch = time.tick_now()
        reply(call.stream, .Touch)
    }
    if time.tick_since(call.stream.last_seen) >= ACTIVE_TIMEOUT {
        local_failure(call, "remote stream timed out; result may be unknown")
        return true
    }
    if call.out_pos == call.out_len {
        packet: [MESSAGE_MAX]byte
        message := read_message(call.stream, packet[:])
        if message != nil {
            op := Op(message[0])
            call.complete = op == .Done || op == .Failure
            if !call.disconnecting {
                call.out_len = frame_local(call.output[:], message)
                call.out_pos = 0
            }
        }
    }
    flush_stream(call.stream)
    if call.disconnecting && call.complete { return false }
    return true
}

client_daemon :: proc(path: string, endpoint: net.Endpoint, own: ^ecdh.Private_Key, peer: ^ecdh.Public_Key, token: []byte) -> int {
    end := strings.last_index_byte(path, '/')
    if end <= 0 || end == len(path)-1 { return error_exit("socket must be inside an absolute private directory") }
    dir := strings.clone_to_cstring(path[:end])
    defer delete(dir)
    if eco_check_private_dir(dir) != 1 { return error_exit("socket directory must be owned by you and mode 0700") }
    lock_path := fmt.aprintf("%s.lock", path)
    defer delete(lock_path)
    lock_name := strings.clone_to_cstring(lock_path)
    defer delete(lock_name)
    lock := eco_lock_local(lock_name)
    if lock < 0 { return error_exit("another client daemon owns the socket") }
    defer _ = eco_close(lock)
    name := strings.clone_to_cstring(path)
    defer delete(name)
    if eco_prepare_socket(name) < 0 { return error_exit("cannot remove stale socket") }
    listener := eco_listen_local(name)
    if listener < 0 { return error_exit("cannot listen on the local socket") }
    defer _ = eco_unlink(name)
    defer _ = eco_close(listener)
    udp, err := net.make_unbound_udp_socket(family(endpoint))
    if err != nil { return error_exit("cannot open UDP", err) }
    defer net.close(udp)
    if eco_fd_setup(c.int(udp), 1) < 0 { return error_exit("cannot configure UDP socket") }

    bridge := Bridge{endpoint = endpoint, udp = udp, own = own, peer = peer, idle = time.tick_now(), token = token}
    defer {
        for &call in bridge.calls { close_local(&bridge, &call) }
        if bridge.link != nil { close_client_link(&bridge.link) }
    }
    packet: [MAX_PACKET+1]byte
    for eco_stopping() == 0 {
        for _ in 0..<64 {
            n, from, read_err := net.recv_udp(udp, packet[:])
            if read_err != nil { break }
            if bridge.link == nil { continue }
            header, ok := parse_header(packet[:n])
            if ok && header.id == bridge.link.id {
                receive_record(bridge.link, header, from, packet[:n], false)
            }
        }
        for &call in bridge.calls {
            if call != nil { continue }
            fd := eco_accept_local(listener)
            if fd < 0 { break }
            call = new(Local_Call)
            call.fd, call.opened, call.last_touch = fd, time.tick_now(), time.tick_now()
        }

        fds, events: [66]c.int
        fds[0], events[0] = c.int(udp), POLL_READ
        fds[1], events[1] = listener, POLL_READ
        count := 2
        active := false
        deadline: c.int = 1000
        for &call in bridge.calls {
            if call == nil { continue }
            active = true
            if !forward_local(&bridge, call) {
                close_local(&bridge, &call)
                continue
            }
            deadline = min(deadline, 10)
            if call.fd >= 0 {
                mask: c.int
                if !call.complete && (call.stream == nil || ikcp_waitsnd(call.stream.kcp) < CALL_QUEUE) {
                    mask |= POLL_READ
                }
                if call.out_pos < call.out_len { mask |= POLL_WRITE }
                fds[count], events[count] = call.fd, mask
                count += 1
            }
        }
        if active {
            bridge.idle = time.tick_now()
        } else {
            if time.tick_since(bridge.idle) >= IDLE_LIFETIME { break }
            if bridge.link != nil {
                if time.tick_since(bridge.link.seen) > 60*time.Second ||
                   time.tick_since(bridge.link.born) >= SESSION_LIFETIME-time.Minute || bridge.serial >= max(u32)-STREAM_HISTORY {
                    close_client_link(&bridge.link)
                } else if time.tick_since(bridge.keepalive) >= 25*time.Second {
                    _ = send_record(bridge.link, .Keepalive, []byte{0}, bridge.link.remote)
                    bridge.keepalive = time.tick_now()
                }
            }
        }
        _ = eco_poll(raw_data(fds[:]), raw_data(events[:]), c.int(count), deadline)
    }
    return 0
}

close_client_link :: proc(slot: ^^Link) {
    link := slot^
    _ = send_record(link, .Close, []byte{0}, link.remote)
    free_link(slot)
}
