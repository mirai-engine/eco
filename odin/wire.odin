package eco

import "base:runtime"
import "core:c"
import "core:crypto"
import "core:crypto/ecdh"
import "core:crypto/noise"
import "core:net"
import "core:time"

when ODIN_OS == .Windows {
    foreign import platform "../.eco-deps/eco_platform.lib"
} else {
    foreign import platform "../.eco-deps/libeco_platform.a"
}

@(default_calling_convention="c")
foreign platform {
    eco_install_signals :: proc() ---
    eco_stopping :: proc() -> c.int ---
    eco_listening :: proc(port: c.int) ---
    eco_ring_ready :: proc() ---
    eco_socket_fd :: proc(native: uintptr) -> c.int ---
    eco_wait :: proc(fd, timeout: c.int) -> c.int ---
    eco_fd_setup :: proc(fd, nonblock: c.int) -> c.int ---
    eco_poll :: proc(fds, events: [^]c.int, count, timeout: c.int) -> c.int ---
    eco_listen_local :: proc(name: cstring) -> c.int ---
    eco_connect_local :: proc(name: cstring) -> c.int ---
    eco_accept_local :: proc(listener: c.int) -> c.int ---
    eco_read :: proc(fd: c.int, buf: rawptr, count: c.int) -> c.int ---
    eco_write :: proc(fd: c.int, buf: rawptr, count: c.int) -> c.int ---
    eco_close :: proc(fd: c.int) -> c.int ---
    eco_unlink :: proc(name: cstring) -> c.int ---
    eco_root :: proc(name: cstring) -> c.int ---
    eco_parent :: proc(root: c.int, path: cstring, leaf: [^]byte, capacity: c.int) -> c.int ---
    eco_open :: proc(dir: c.int, leaf: cstring, want_dir: c.int) -> c.int ---
    eco_stat :: proc(dir: c.int, leaf: cstring, size: ^u64, kind: ^u8, stamp: ^u64) -> c.int ---
    eco_directory :: proc(fd: c.int) -> rawptr ---
    eco_dir_close :: proc(handle: rawptr) ---
    eco_dir_next :: proc(handle: rawptr, out: rawptr, capacity: c.int) -> c.int ---
    eco_file_create :: proc(dir: c.int, name: cstring) -> c.int ---
    eco_rename :: proc(dir: c.int, from, to: cstring) -> c.int ---
    eco_remove :: proc(dir: c.int, name: cstring) -> c.int ---
    eco_sync :: proc(fd: c.int) -> c.int ---
    eco_spawn :: proc(args: [^]cstring, fds: [^]c.int, workdir: c.int, input: ^c.int, scope: c.int) -> c.int ---
    eco_spawn_pty :: proc(args: [^]cstring, fd: ^c.int, workdir: c.int, rows, cols: u16, scope: c.int) -> c.int ---
    eco_terminal_resize :: proc(fd: c.int, rows, cols: u16) -> c.int ---
    eco_terminal_size :: proc(fd: c.int, rows, cols: ^u16) -> c.int ---
    eco_terminal_restore :: proc() ---
    eco_terminal_raw :: proc(fd: c.int) -> c.int ---
    eco_child_poll :: proc(pid: c.int, status: ^c.int) -> c.int ---
    eco_child_kill :: proc(pid: c.int) ---
    eco_child_events :: proc() -> c.int ---
    eco_scope_supported :: proc() -> c.int ---
    eco_ring_setup :: proc() -> c.int ---
    eco_ring_close :: proc() ---

    ikcp_create :: proc(conv: u32, user: rawptr) -> rawptr ---
    ikcp_release :: proc(kcp: rawptr) ---
    ikcp_setoutput :: proc(kcp: rawptr, callback: proc "c" (rawptr, c.int, rawptr, rawptr) -> c.int) ---
    ikcp_recv :: proc(kcp, data: rawptr, size: c.int) -> c.int ---
    ikcp_send :: proc(kcp, data: rawptr, size: c.int) -> c.int ---
    ikcp_input :: proc(kcp, data: rawptr, size: c.long) -> c.int ---
    ikcp_update :: proc(kcp: rawptr, now: u32) ---
    ikcp_flush :: proc(kcp: rawptr) ---
    ikcp_nodelay :: proc(kcp: rawptr, nodelay, interval, resend, nc: c.int) -> c.int ---
    ikcp_wndsize :: proc(kcp: rawptr, send, receive: c.int) -> c.int ---
    ikcp_setmtu :: proc(kcp: rawptr, mtu: c.int) -> c.int ---
    ikcp_waitsnd :: proc(kcp: rawptr) -> c.int ---
}

NOISE_SUITE :: "Noise_IK_25519_ChaChaPoly_BLAKE2s"
HEADER_SIZE :: 24
HELLO_OVERHEAD :: 96
HELLO_MIN :: HEADER_SIZE+HELLO_OVERHEAD+1
HELLO_MAX :: HELLO_MIN+CAP_MAX
MAX_PACKET :: 1200
KCP_MTU :: MAX_PACKET - HEADER_SIZE - noise.TAG_SIZE
KCP_OVERHEAD :: 24
MESSAGE_MAX :: KCP_MTU - KCP_OVERHEAD
STREAM_MAX :: 16
STREAM_HISTORY :: 128
REPLAY_WINDOW :: 512
SESSION_LIFETIME :: 15 * time.Minute
IDLE_LIFETIME :: 2 * time.Minute
ACTIVE_TIMEOUT :: 45 * time.Second
RECORD_LIMIT :: 1 << 32
POLL_READ :: 1
POLL_WRITE :: 4
POLL_CLOSED :: 8 | 16 | 32

Packet_Kind :: enum u8 {
    Hello = 1, Welcome, Data, Path_Challenge, Path_Response, Confirm, Keepalive, Close, Query, Query_Result,
    Pair, Pair_Reply,
}

Record :: struct {
    kind: Packet_Kind,
    id, nonce: u64,
}

Replay :: struct {
    high: u64,
    entries: [REPLAY_WINDOW]u64,
}

Link :: struct {
    id: u64,
    udp: net.UDP_Socket,
    remote: net.Endpoint,
    cipher: noise.Cipher_States,
    send_number: u64,
    replay: Replay,
    born, seen: time.Tick,
    verified, closing: bool,
    scope: c.int,
    grant_expiry: u64,
    rights: u8,
    confined: bool,
    scope_key, client_key: [32]byte,
    path: net.Endpoint,
    challenge: [16]byte,
    challenge_at: time.Tick,
    client_hello: [HELLO_MAX]byte,
    server_hello: [HEADER_SIZE+49]byte,
    hello_len, welcome_len: int,
    high_stream: u32,
    history: [STREAM_HISTORY]u32,
    streams: [STREAM_MAX]^Stream,
    pacer: ^Pacer,
}

Stream :: struct {
    id: u32,
    link: ^Link,
    kcp: rawptr,
    last_seen, began: time.Tick,
    application: rawptr,
    finished, bulk: bool,
}

get_u32 :: proc(data: []byte) -> u32 {
    return u32(data[0]) | u32(data[1]) << 8 | u32(data[2]) << 16 | u32(data[3]) << 24
}

get_u64 :: proc(data: []byte) -> u64 {
    return u64(get_u32(data)) | u64(get_u32(data[4:])) << 32
}

put_u32 :: proc(data: []byte, value: u32) {
    for i in 0..<4 {
        data[i] = u8(value >> u32(8 * i))
    }
}

put_u64 :: proc(data: []byte, value: u64) {
    put_u32(data, u32(value))
    put_u32(data[4:], u32(value >> 32))
}

write_header :: proc(dst: []byte, kind: Packet_Kind, id, nonce: u64) {
    copy(dst, "ECO2")
    dst[4] = u8(kind)
    dst[5], dst[6], dst[7] = 0, 0, 0
    put_u64(dst[8:], id)
    put_u64(dst[16:], nonce)
}

parse_header :: proc(data: []byte) -> (Record, bool) {
    if len(data) <= HEADER_SIZE || len(data) > MAX_PACKET || string(data[:4]) != "ECO2" ||
       data[5] | data[6] | data[7] != 0 {
        return {}, false
    }
    kind := Packet_Kind(data[4])
    id, nonce := get_u64(data[8:]), get_u64(data[16:])
    if kind < .Hello || kind > .Pair_Reply || id == 0 {
        return {}, false
    }
    return {kind, id, nonce}, true
}

replay_allowed :: proc(r: ^Replay, nonce: u64) -> bool {
    if nonce == 0 || nonce >= RECORD_LIMIT || (r.high >= REPLAY_WINDOW && nonce <= r.high - REPLAY_WINDOW) {
        return false
    }
    return r.entries[nonce % REPLAY_WINDOW] != nonce
}

replay_commit :: proc(r: ^Replay, nonce: u64) {
    r.high = max(r.high, nonce)
    r.entries[nonce % REPLAY_WINDOW] = nonce
}

random_bytes :: proc(dst: []byte) {
    crypto.rand_bytes(dst)
}

tick_ms :: proc() -> u32 {
    return u32(time.tick_now()._nsec / 1_000_000)
}

family :: proc(ep: net.Endpoint) -> net.Address_Family {
    if _, ipv6 := ep.address.(net.IP6_Address); ipv6 {
        return .IP6
    }
    return .IP4
}

same_endpoint :: proc(a, b: net.Endpoint) -> bool {
    if a.port != b.port { return false }
    switch addr in a.address {
    case net.IP4_Address:
        other, ok := b.address.(net.IP4_Address)
        return ok && addr == other
    case net.IP6_Address:
        other, ok := b.address.(net.IP6_Address)
        return ok && addr == other
    case:
        return false
    }
    return false
}

seal :: proc(link: ^Link, kind: Packet_Kind, data: []byte, packet: []byte) -> []byte {
    if link.send_number + 1 >= RECORD_LIMIT || len(data) > KCP_MTU { return nil }
    link.send_number += 1
    write_header(packet, kind, link.id, link.send_number)
    if noise.cipherstates_set_n(&link.cipher, true, link.send_number) != .Ok { return nil }
    ciphertext, status := noise.seal_message(&link.cipher, packet[:HEADER_SIZE], data,
        packet[HEADER_SIZE:HEADER_SIZE+len(data)+noise.TAG_SIZE])
    if status != .Ok { return nil }
    return packet[:HEADER_SIZE+len(ciphertext)]
}

unseal :: proc(link: ^Link, header: Record, packet, dst: []byte) -> ([]byte, bool) {
    if len(packet) <= HEADER_SIZE+noise.TAG_SIZE || !replay_allowed(&link.replay, header.nonce) {
        return nil, false
    }
    if noise.cipherstates_set_n(&link.cipher, false, header.nonce) != .Ok { return nil, false }
    plain, status := noise.open_message(&link.cipher, packet[:HEADER_SIZE], packet[HEADER_SIZE:],
        dst[:len(packet)-HEADER_SIZE-noise.TAG_SIZE])
    if status != .Ok { return nil, false }
    replay_commit(&link.replay, header.nonce)
    return plain, true
}

send_record :: proc(link: ^Link, kind: Packet_Kind, payload: []byte, endpoint: net.Endpoint) -> bool {
    packet: [MAX_PACKET]byte
    data := seal(link, kind, payload, packet[:])
    if data == nil { return false }
    _, err := net.send_udp(link.udp, data, endpoint)
    return err == nil
}

// On a new address, prove return-path reachability before directing stream traffic there.
handle_path :: proc(link: ^Link, header: Record, from: net.Endpoint, plain: []byte) -> bool {
    if header.kind == .Path_Challenge {
        if len(plain) == 16 { _ = send_record(link, .Path_Response, plain, from) }
        return false
    }
    if header.kind == .Path_Response {
        if len(plain) == 16 && same_endpoint(from, link.path) && link.challenge_at != {} &&
           time.tick_since(link.challenge_at) <= 3*time.Second &&
           string(plain) == string(link.challenge[:]) {
            link.remote = from
            link.challenge_at = {}
            link.seen = time.tick_now()
        }
        return false
    }
    if !same_endpoint(from, link.remote) {
        if !link.verified { return false }
        if link.challenge_at == {} || time.tick_since(link.challenge_at) >= 250*time.Millisecond {
            random_bytes(link.challenge[:])
            link.challenge_at = time.tick_now()
            link.path = from
            _ = send_record(link, .Path_Challenge, link.challenge[:], from)
        }
        return false
    }
    return true
}

connect_link :: proc(udp: net.UDP_Socket, endpoint: net.Endpoint, own: ^ecdh.Private_Key,
                     peer: ^ecdh.Public_Key, token: []byte, early_ping: bool, link: ^Link, udp_fd: c.int) -> bool {
    sid: [8]byte
    random_bytes(sid[:])
    link.id = get_u64(sid[:]) | 1
    link.udp, link.remote = udp, endpoint
    write_header(link.client_hello[:], .Hello, link.id, 0)
    handshake: noise.Handshake_State
    defer noise.handshake_reset(&handshake)
    if noise.handshake_init(&handshake, true, link.client_hello[:16], own, peer, NOISE_SUITE) != .Ok {
        return false
    }
    data: [1+CAP_MAX]byte
    if len(token) > CAP_MAX { return false }
    if early_ping { data[0] = 1 }
    copy(data[1:], token)
    hello, status := noise.handshake_write_message(&handshake, data[:1+len(token)], link.client_hello[HEADER_SIZE:])
    if status != .Handshake_Pending { return false }
    link.hello_len = HEADER_SIZE+len(hello)
    packet: [MAX_PACKET+1]byte
    deadline := time.tick_now()
    retry := time.Tick{}
    for time.tick_since(deadline) < 4*time.Second && eco_stopping() == 0 {
        if retry == {} || time.tick_since(retry) >= 100*time.Millisecond {
            _, _ = net.send_udp(udp, link.client_hello[:link.hello_len], endpoint)
            retry = time.tick_now()
        }
        if eco_wait(udp_fd, 100) == 0 { continue }
        n, from, err := net.recv_udp(udp, packet[:])
        if err != nil || !same_endpoint(from, endpoint) { continue }
        header, ok := parse_header(packet[:n])
        if !ok || header.kind != .Welcome || header.id != link.id || header.nonce != 0 || n != HEADER_SIZE+49 {
            continue
        }
        // Noise read failure mutates the state, so validate candidates on a copy.
        candidate := handshake
        response: [1]byte
        contents, result := noise.handshake_read_message(&candidate, packet[HEADER_SIZE:n], response[:])
        if result == .Handshake_Complete && len(contents) == 1 && contents[0] == data[0] &&
           noise.handshake_split(&candidate, &link.cipher) == .Ok {
            noise.handshake_reset(&candidate)
            link.born = time.tick_now()
            link.seen, link.verified = link.born, true
            _ = send_record(link, .Close if early_ping else .Confirm, []byte{0}, endpoint)
            return true
        }
        noise.handshake_reset(&candidate)
    }
    return false
}

accept_link :: proc(udp: net.UDP_Socket, from: net.Endpoint, packet: []byte, header: Record,
                    own: ^ecdh.Private_Key, clients: string, root: c.int,
                    policy: ^Policy) -> ^Link {
    if header.nonce != 0 || len(packet) < HELLO_MIN || len(packet) > HELLO_MAX { return nil }
    handshake: noise.Handshake_State
    defer noise.handshake_reset(&handshake)
    if noise.handshake_init(&handshake, false, packet[:16], own, nil, NOISE_SUITE) != .Ok { return nil }
    decoded: [1+CAP_MAX]byte
    early, status := noise.handshake_read_message(&handshake, packet[HEADER_SIZE:], decoded[:])
    if status != .Handshake_Pending || len(early) == 0 || early[0] > 1 ||
       !client_authorized(clients, &handshake.rs) {
        return nil
    }
    grant, permitted := verify_capability(policy, &handshake.rs, early[1:])
    if !permitted { return nil }
    scope := open_scope(root, grant)
    if scope < 0 { return nil }
    link := new(Link)
    link.scope, link.rights, link.grant_expiry = scope, grant.mask, grant.expiry
    link.confined = grant.scope != "." && grant.mask & CAP_RUN != 0
    if link.confined { link.scope_key = scope_key(grant.scope) }
    link.id, link.udp, link.remote = header.id, udp, from
    ecdh.public_key_bytes(&handshake.rs, link.client_key[:])
    link.hello_len = copy(link.client_hello[:], packet)
    write_header(link.server_hello[:], .Welcome, header.id, 0)
    reply, result := noise.handshake_write_message(&handshake, early[:1], link.server_hello[HEADER_SIZE:])
    if result != .Handshake_Complete || noise.handshake_split(&handshake, &link.cipher) != .Ok {
        _ = eco_close(link.scope)
        free(link)
        return nil
    }
    link.born = time.tick_now()
    link.seen = link.born
    link.welcome_len = HEADER_SIZE+len(reply)
    _, _ = net.send_udp(udp, link.server_hello[:link.welcome_len], from)
    return link
}

kcp_output :: proc "c" (data: rawptr, length: c.int, _: rawptr, user: rawptr) -> c.int {
    context = runtime.default_context()
    stream := cast(^Stream)user
    link := stream.link
    // KCP will retransmit when a datagram is dropped, including a local send error.
    bytes := (cast([^]byte)data)[:length]
    if stream.bulk && bulk_segments(bytes) {
        paced_output(link, bytes)
    } else {
        _ = send_record(link, .Data, bytes, link.remote)
    }
    return 0
}

find_stream :: proc(link: ^Link, id: u32) -> ^Stream {
    for stream in link.streams {
        if stream != nil && stream.id == id { return stream }
    }
    return nil
}

new_stream :: proc(link: ^Link, id: u32) -> ^Stream {
    if id == 0 || (link.high_stream >= STREAM_HISTORY && id <= link.high_stream - STREAM_HISTORY) ||
       link.history[id % STREAM_HISTORY] == id {
        return nil
    }
    for &slot in link.streams {
        if slot != nil { continue }
        stream := new(Stream)
        stream.id, stream.link = id, link
        stream.began = time.tick_now()
        stream.last_seen = stream.began
        stream.kcp = ikcp_create(id, stream)
        if stream.kcp == nil { free(stream); return nil }
        if ikcp_setmtu(stream.kcp, KCP_MTU) < 0 {
            ikcp_release(stream.kcp)
            free(stream)
            return nil
        }
        ikcp_setoutput(stream.kcp, kcp_output)
        _ = ikcp_nodelay(stream.kcp, 1, 10, 2, 0)
        _ = ikcp_wndsize(stream.kcp, 64, 128)
        ikcp_update(stream.kcp, tick_ms())
        link.high_stream = max(link.high_stream, id)
        link.history[id % STREAM_HISTORY] = id
        slot = stream
        return stream
    }
    return nil
}

free_stream :: proc(slot: ^^Stream) {
    ikcp_release(slot^.kcp)
    free(slot^)
    slot^ = nil
}

send_message :: proc(stream: ^Stream, opcode: u8, payload: []byte = nil) -> bool {
    if len(payload) >= MESSAGE_MAX { return false }
    message: [MESSAGE_MAX]byte
    message[0] = opcode
    copy(message[1:], payload)
    return ikcp_send(stream.kcp, raw_data(message[:]), c.int(1+len(payload))) >= 0
}

// Each application message occupies one KCP segment. Reject malformed segments before KCP can queue
// them, cap receive-window distance, and reject reserved/unsupported fragmentation.
valid_segments :: proc(data: []byte) -> bool {
    remaining := data
    for len(remaining) >= KCP_OVERHEAD {
        cmd, fragments := remaining[4], remaining[5]
        size := get_u32(remaining[20:])
        if fragments != 0 || cmd < 81 || cmd > 84 || int(size) > len(remaining)-KCP_OVERHEAD ||
           (cmd != 81 && size != 0) || (cmd == 81 && size == 0) ||
           get_u32(remaining) != get_u32(data) {
            return false
        }
        remaining = remaining[KCP_OVERHEAD+int(size):]
    }
    return len(data) >= KCP_OVERHEAD && len(remaining) == 0
}

receive_record :: proc(link: ^Link, header: Record, from: net.Endpoint, packet, buffer: []byte, accept_new: bool) -> []byte {
    if header.kind < .Data { return nil }
    plain, ok := unseal(link, header, packet, buffer[:])
    if !ok || !handle_path(link, header, from, plain) { return nil }
    link.seen = time.tick_now()
    link.verified = true
    if header.kind == .Close { link.closing = true; return nil }
    if header.kind == .Keepalive {
        if accept_new { _ = send_record(link, .Keepalive, plain, link.remote) }
        return nil
    }
    if header.kind == (.Query if accept_new else .Query_Result) { return plain }
    if header.kind != .Data || !valid_segments(plain) { return nil }
    id := get_u32(plain)
    stream := find_stream(link, id)
    if stream == nil && accept_new && plain[4] == 81 && get_u32(plain[12:]) == 0 {
        stream = new_stream(link, id)
    }
    if stream == nil { return nil }
    if ikcp_input(stream.kcp, raw_data(plain), c.long(len(plain))) >= 0 {
        stream.last_seen = link.seen
    }
    return nil
}

read_message :: proc(stream: ^Stream, buffer: []byte) -> []byte {
    n := ikcp_recv(stream.kcp, raw_data(buffer), c.int(len(buffer)))
    if n <= 0 { return nil }
    return buffer[:n]
}

flush_stream :: proc(stream: ^Stream) {
    ikcp_update(stream.kcp, tick_ms())
    ikcp_flush(stream.kcp)
}

reset_link :: proc(link: ^Link) {
    release_pacer(link)
    noise.cipherstates_reset(&link.cipher)
}
