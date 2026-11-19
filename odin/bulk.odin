package eco

import "core:c"
import "core:crypto"
import "core:crypto/ecdh"
import "core:crypto/noise"
import "core:encoding/hex"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:time"
import "deps:blake3"

when ODIN_OS == .Windows {
    foreign import platform "../.eco-deps/eco_platform.lib"
} else {
    foreign import platform "../.eco-deps/libeco_platform.a"
}
@(default_calling_convention="c")
foreign platform {
    eco_bulk_socket :: proc(fd: c.int) -> c.int ---
    eco_bulk_worker :: proc(socket, scope: c.int) -> c.int ---
}

BULK_PROLOGUE :: string("ECO2 file transfer v2")
BULK_DATA :: 64*1024 - 32
BULK_CAPACITY :: BULK_DATA + 3 + noise.TAG_SIZE
BULK_PEERS :: 8

Bulk_Pending :: struct {
    fd: c.int,
    used, sent, welcome_length: int,
    start: time.Tick,
    scope: c.int,
    rights: u8,
    expiry: u64,
    transcript, seed: [32]byte,
    cipher: noise.Cipher_States,
    welcome: [64]byte,
    data: [2+96+CAP_MAX]byte,
}
Bulk_Server :: struct {
    listener: net.TCP_Socket,
    listen_fd: c.int,
    enabled: bool,
    pending: [BULK_PEERS]Bulk_Pending,
    workers: [BULK_PEERS]c.int,
}

enable_bulk :: proc(endpoint: net.Endpoint, b: ^Bulk_Server) -> bool {
    sock, err := net.listen_tcp(endpoint, BULK_PEERS)
    if err != nil { return false }
    fd := eco_socket_fd(uintptr(sock))
    if fd < 0 { net.close(sock); return false }
    if eco_fd_setup(fd, 1) < 0 { _ = eco_close(fd); return false }
    b.enabled, b.listener, b.listen_fd = true, sock, fd
    for &p in b.pending { p.fd, p.scope = -1, -1 }
    return true
}

clear_bulk :: proc(b: ^Bulk_Server) {
    if !b.enabled { return }
    for &p in b.pending { close_bulk_pending(&p) }
    for pid in b.workers { if pid > 0 { eco_child_kill(pid) } }
    _ = eco_close(b.listen_fd)
}

bulk_enabled :: proc() -> bool {
    value: [64]byte
    return os.get_env(value[:], "ECO_ODIN_BULK_TCP") == "1"
}

bulk_length :: proc(header: []byte) -> int {
    return int(header[0]) | int(header[1]) << 8
}

bulk_header :: proc(header: []byte, length: int) {
    header[0], header[1] = u8(length), u8(length >> 8)
}

bulk_plain_send :: proc(fd: c.int, message: []byte) -> bool {
    prefix: [2]byte
    bulk_header(prefix[:], len(message))
    return write_fd(fd, prefix[:]) && write_fd(fd, message)
}

bulk_plain_read :: proc(fd: c.int, buffer: []byte) -> []byte {
    prefix: [2]byte
    if !read_fully(fd, prefix[:]) { return nil }
    size := bulk_length(prefix[:])
    if size == 0 || size > len(buffer) || !read_fully(fd, buffer[:size]) { return nil }
    return buffer[:size]
}

bulk_send :: proc(fd: c.int, cipher: ^Bulk_Cipher, buffer: []byte, op: Op, data: []byte = nil) -> bool {
    if len(data) > BULK_DATA { return false }
    size := 1+len(data)
    bulk_header(buffer[:2], size+noise.TAG_SIZE)
    buffer[2] = byte(op)
    copy(buffer[3:], data)
    end := 2+size+noise.TAG_SIZE
    return bulk_crypt(&cipher.send, buffer[:2], buffer[2:2+size], buffer[2+size:end], true) &&
           write_fd(fd, buffer[:end])
}

bulk_receive :: proc(fd: c.int, cipher: ^Bulk_Cipher, buffer: []byte) -> []byte {
    if !read_fully(fd, buffer[:2]) { return nil }
    size := bulk_length(buffer[:2])
    if size <= noise.TAG_SIZE || size > len(buffer)-2 || !read_fully(fd, buffer[2:2+size]) { return nil }
    plain := buffer[2:2+size-noise.TAG_SIZE]
    valid := bulk_crypt(&cipher.receive, buffer[:2], plain, buffer[2+len(plain):2+size], false)
    return plain if valid else nil
}

bulk_fail :: proc(fd: c.int, cipher: ^Bulk_Cipher, buffer: []byte, message: string) {
    _ = bulk_send(fd, cipher, buffer, .Failure, transmute([]byte)message)
}

bulk_server_transfer :: proc(fd, scope: c.int, rights: u8, access: Access, cipher: ^Bulk_Cipher,
                             expiry: u64) -> bool {
    buffer: [BULK_CAPACITY]byte
    request := bulk_receive(fd, cipher, buffer[:])
    if len(request) < 2 || (request[0] != byte(Op.Read) && request[0] != byte(Op.Write)) { return false }
    if expiry != 0 {
        // Periodic checks bound a transfer even when activity keeps the socket timeout from firing.
        if u64(time.to_unix_seconds(time.now())) >= expiry { return false }
    }
    download := request[0] == byte(Op.Read)
    if (download && rights & CAP_READ == 0) ||
       (!download && (rights & CAP_WRITE == 0 || (access != .Write && access != .Run))) {
        bulk_fail(fd, cipher, buffer[:], "bulk transfer is not permitted")
        return false
    }
    leaf: [256]byte
    parent := parent_for(scope, request[1:], &leaf)
    if parent < 0 {
        bulk_fail(fd, cipher, buffer[:], "invalid or inaccessible path")
        return false
    }
    defer _ = eco_close(parent)
    name := cstring(&leaf[0])
    hasher: blake3.Hasher
    blake3.init(&hasher)
    if download {
        file := eco_open(parent, name, 0)
        if file < 0 {
            bulk_fail(fd, cipher, buffer[:], "cannot open regular file")
            return false
        }
        defer _ = eco_close(file)
        for expiry == 0 || u64(time.to_unix_seconds(time.now())) < expiry {
            n := eco_read(file, &buffer[3], BULK_DATA)
            if n < 0 { return false }
            if n == 0 {
                digest := blake3.final(&hasher)
                return bulk_send(fd, cipher, buffer[:], .Digest, digest[:])
            }
            blake3.update(&hasher, buffer[3:3+n])
            if !bulk_send(fd, cipher, buffer[:], .Stdout, buffer[3:3+n]) { return false }
        }
        return false
    }

    random: [16]byte
    random_bytes(random[:])
    encoded := hex.encode(random[:])
    defer delete(encoded)
    temporary: [48]byte
    copy(temporary[:], ".eco-part-")
    copy(temporary[10:], encoded)
    tmp := cstring(&temporary[0])
    file := eco_file_create(parent, tmp)
    if file < 0 {
        bulk_fail(fd, cipher, buffer[:], "cannot create temporary file")
        return false
    }
    defer _ = eco_close(file)
    defer _ = eco_remove(parent, tmp)
    if !bulk_send(fd, cipher, buffer[:], .Ready) { return false }
    for expiry == 0 || u64(time.to_unix_seconds(time.now())) < expiry {
        frame := bulk_receive(fd, cipher, buffer[:])
        if len(frame) == 0 { return false }
        if frame[0] == byte(Op.Digest) {
            digest := blake3.final(&hasher)
            if string(frame[1:]) != string(digest[:]) || eco_sync(file) < 0 ||
               (expiry != 0 && u64(time.to_unix_seconds(time.now())) >= expiry) ||
               eco_rename(parent, tmp, name) < 0 {
                bulk_fail(fd, cipher, buffer[:], "cannot verify or commit upload")
                return false
            }
            return bulk_send(fd, cipher, buffer[:], .Done)
        }
        if frame[0] != byte(Op.Upload) || len(frame) == 1 || !write_fd(file, frame[1:]) { return false }
        blake3.update(&hasher, frame[1:])
    }
    return false
}

close_bulk_pending :: proc(p: ^Bulk_Pending) {
    close_fd(&p.fd)
    close_fd(&p.scope)
    noise.cipherstates_reset(&p.cipher)
    crypto.zero_explicit(&p.seed, len(p.seed))
}

bulk_accept_hello :: proc(server: ^Server, p: ^Bulk_Pending, hello: []byte) -> bool {
    handshake: noise.Handshake_State
    defer noise.handshake_reset(&handshake)
    protocol := transmute([]byte)BULK_PROLOGUE
    if noise.handshake_init(&handshake, false, protocol, &server.own, nil, NOISE_SUITE) != .Ok { return false }
    token: [CAP_MAX]byte
    payload, status := noise.handshake_read_message(&handshake, hello, token[:])
    if status != .Handshake_Pending || !client_authorized(server.clients, &handshake.rs) { return false }
    grant, valid := verify_capability(&server.policy, &handshake.rs, payload)
    if !valid { return false }
    p.scope = open_scope(server.root, grant)
    if p.scope < 0 { return false }
    p.rights, p.expiry = grant.mask, grant.expiry
    welcome, result := noise.handshake_write_message(&handshake, nil, p.welcome[2:])
    if result != .Handshake_Complete || noise.handshake_split(&handshake, &p.cipher) != .Ok { return false }
    transcript, transcript_status := noise.handshake_hash(&handshake)
    if transcript_status != .Ok || len(transcript) != len(p.transcript) { return false }
    copy(p.transcript[:], transcript)
    bulk_header(p.welcome[:2], len(welcome))
    p.welcome_length = 2+len(welcome)
    p.used = 0
    return true
}

bulk_serve_worker :: proc(p: ^Bulk_Pending, access: Access) -> ! {
    if eco_bulk_socket(3) < 0 { os.exit(125) }
    cipher: Bulk_Cipher
    bulk_cipher_init(&cipher, p.transcript[:], p.seed[:], false)
    crypto.zero_explicit(&p.seed, len(p.seed))
    noise.cipherstates_reset(&p.cipher)
    _ = bulk_server_transfer(3, 4, p.rights, access, &cipher, p.expiry)
    bulk_cipher_free(&cipher)
    os.exit(0)
}

poll_bulk_peer :: proc(server: ^Server, p: ^Bulk_Pending, worker: ^c.int) -> bool {
    if p.scope < 0 {
        for _ in 0..<2 {
            want := 2
            if p.used >= 2 {
                length := bulk_length(p.data[:2])
                if length < 96 || length > len(p.data)-2 { return false }
                want += length
            }
            n := eco_read(p.fd, &p.data[p.used], c.int(want-p.used))
            if n == -2 { return true }
            if n <= 0 { return false }
            p.used += int(n)
            if p.used == want && want > 2 && !bulk_accept_hello(server, p, p.data[2:want]) {
                return false
            }
        }
        if p.scope < 0 { return true }
    }
    if p.sent < p.welcome_length {
        remainder := p.welcome[p.sent:p.welcome_length]
        n := eco_write(p.fd, raw_data(remainder), c.int(len(remainder)))
        if n == -2 { return true }
        if n <= 0 { return false }
        p.sent += int(n)
        if p.sent < p.welcome_length { return true }
    }

    // A replayed first IK message cannot prove possession of the fresh responder session key.
    confirm_len :: 2+1+32+noise.TAG_SIZE
    n := eco_read(p.fd, &p.data[p.used], c.int(confirm_len-p.used))
    if n == -2 { return true }
    if n <= 0 { return false }
    p.used += int(n)
    if p.used < confirm_len { return true }
    if bulk_length(p.data[:2]) != confirm_len-2 { return false }
    confirmation, result := noise.open_message(&p.cipher, p.data[:2], p.data[2:confirm_len],
                                                p.data[2:confirm_len-noise.TAG_SIZE])
    if result != .Ok || len(confirmation) != 33 || confirmation[0] != byte(Op.Touch) { return false }
    copy(p.seed[:], confirmation[1:])
    crypto.zero_explicit(raw_data(confirmation), len(confirmation))
    noise.cipherstates_reset(&p.cipher)

    when ODIN_OS == .Windows {
        worker^ = start_windows_bulk(p, server.access)
        if worker^ > 0 { p.fd = -1 }
    } else {
        pid := eco_bulk_worker(p.fd, p.scope)
        if pid == 0 { bulk_serve_worker(p, server.access) }
        if pid > 0 { worker^ = pid }
    }
    return false
}

poll_bulk :: proc(b: ^Bulk_Server, server: ^Server, fds, events: []c.int, count: ^int, timeout: ^c.int) {
    if !b.enabled { return }
    for &pid in b.workers {
        if pid <= 0 { continue }
        result: c.int
        if eco_child_poll(pid, &result) != 0 { pid = 0 }
    }
    for &p in b.pending {
        if p.fd < 0 {
            socket, _, err := net.accept_tcp(b.listener)
            if err != nil { continue }
            p.fd = eco_socket_fd(uintptr(socket))
            if p.fd < 0 { net.close(socket); continue }
            if eco_fd_setup(p.fd, 1) < 0 { close_bulk_pending(&p); continue }
            p.start, p.used, p.sent, p.welcome_length = time.tick_now(), 0, 0, 0
        }
        worker: ^c.int
        for &pid in b.workers { if pid == 0 { worker = &pid; break } }
        if worker == nil || time.tick_since(p.start) >= 3*time.Second || !poll_bulk_peer(server, &p, worker) {
            close_bulk_pending(&p)
            continue
        }
        mask: c.int = POLL_WRITE if p.sent < p.welcome_length else POLL_READ
        fds[count^], events[count^] = p.fd, mask
        count^ += 1
        timeout^ = min(timeout^, 100)
    }
    fds[count^], events[count^] = b.listen_fd, POLL_READ
    count^ += 1
}

bulk_client :: proc(op: Op, remote, local: string) -> int {
    if len(remote) == 0 || len(remote) >= MESSAGE_MAX { return error_exit("invalid remote path") }
    target := os.get_env("ECO_ODIN_ADDR", context.temp_allocator)
    key := os.get_env("ECO_ODIN_KEY", context.temp_allocator)
    peer_text := client_peer(target)
    endpoint, ok := net.parse_endpoint(target)
    if !ok || endpoint.port <= 0 { return error_exit("bulk TCP requires ECO_ODIN_ADDR") }
    own: ecdh.Private_Key
    peer: ecdh.Public_Key
    defer ecdh.private_key_clear(&own)
    if !load_keys(key, peer_text, &own, &peer) { return error_exit("invalid bulk TCP identity") }
    token: []byte
    if encoded := os.get_env("ECO_ODIN_CAPABILITY", context.temp_allocator); encoded != "" {
        if len(encoded) > CAP_MAX*2 { return error_exit("invalid capability") }
        token, ok = hex.decode(transmute([]byte)encoded, context.temp_allocator)
        if !ok { return error_exit("invalid capability") }
    }

    target_c := strings.clone_to_cstring(target, context.temp_allocator)
    connecting: c.int
    fd := eco_net_open(target_c, 0, &connecting)
    if fd < 0 { return error_exit("cannot connect to bulk TCP") }
    defer _ = eco_close(fd)
    if connecting != 0 {
        fds := [1]c.int{fd}
        events := [1]c.int{POLL_WRITE}
        if eco_poll(raw_data(fds[:]), raw_data(events[:]), 1, 1500) <= 0 || eco_net_ready(fd) != 1 {
            return error_exit("bulk TCP connection failed or timed out")
        }
    }
    if eco_bulk_socket(fd) < 0 { return error_exit("cannot configure bulk TCP socket") }
    handshake: noise.Handshake_State
    defer noise.handshake_reset(&handshake)
    if noise.handshake_init(&handshake, true, transmute([]byte)BULK_PROLOGUE, &own, &peer, NOISE_SUITE) != .Ok {
        return error_exit("cannot start bulk Noise session")
    }
    hello: [96+CAP_MAX]byte
    message, status := noise.handshake_write_message(&handshake, token, hello[:])
    if status != .Handshake_Pending || !bulk_plain_send(fd, message) {
        return error_exit("cannot send bulk handshake")
    }
    welcome: [64]byte
    response := bulk_plain_read(fd, welcome[:])
    if len(response) != 48 { return error_exit("invalid bulk handshake reply") }
    _, status = noise.handshake_read_message(&handshake, response, nil)
    noise_cipher: noise.Cipher_States
    defer noise.cipherstates_reset(&noise_cipher)
    if status != .Handshake_Complete || noise.handshake_split(&handshake, &noise_cipher) != .Ok {
        return error_exit("bulk peer authentication failed")
    }
    transcript, transcript_status := noise.handshake_hash(&handshake)
    if transcript_status != .Ok || len(transcript) != 32 { return error_exit("invalid handshake transcript") }

    cipher: Bulk_Cipher
    defer bulk_cipher_free(&cipher)
    confirmation: [2+1+32+noise.TAG_SIZE]byte
    confirmation[2] = byte(Op.Touch)
    random_bytes(confirmation[3:35])
    bulk_cipher_init(&cipher, transcript, confirmation[3:35], true)
    bulk_header(confirmation[:2], len(confirmation)-2)
    if _, valid := noise.seal_message(&noise_cipher, confirmation[:2], confirmation[2:35],
                                     confirmation[2:]); valid != .Ok || !write_fd(fd, confirmation[:]) {
        return error_exit("cannot confirm bulk Noise session")
    }

    buffer: [BULK_CAPACITY]byte
    if !bulk_send(fd, &cipher, buffer[:], op, transmute([]byte)remote) {
        return error_exit("cannot send file request")
    }
    return bulk_client_get(fd, &cipher, local, buffer[:]) if op == .Read else
           bulk_client_put(fd, &cipher, local, buffer[:])
}

bulk_client_get :: proc(fd: c.int, cipher: ^Bulk_Cipher, path: string, buffer: []byte) -> int {
    random: [16]byte
    random_bytes(random[:])
    temp := fmt.tprintf("%s.eco-part-%s", path, string(hex.encode(random[:], context.temp_allocator)))
    file, err := os.open(temp, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
    if err != nil { return error_exit("cannot create download", err) }
    defer {
        if file != nil { _ = os.close(file) }
        _ = os.remove(temp)
    }
    hasher: blake3.Hasher
    blake3.init(&hasher)
    for {
        frame := bulk_receive(fd, cipher, buffer)
        if len(frame) == 0 { return error_exit("bulk download disconnected") }
        if frame[0] == byte(Op.Failure) { return error_exit(string(frame[1:])) }
        if frame[0] == byte(Op.Digest) {
            digest := blake3.final(&hasher)
            if string(frame[1:]) != string(digest[:]) || os.sync(file) != nil {
                return error_exit("cannot verify download")
            }
            err := os.close(file)
            file = nil
            if err != nil || os.rename(temp, path) != nil { return error_exit("cannot commit download") }
            return 0
        }
        if frame[0] != byte(Op.Stdout) { return error_exit("invalid bulk download record") }
        body := frame[1:]
        n, write_err := os.write(file, body)
        if write_err != nil || n != len(body) { return error_exit("cannot write download") }
        blake3.update(&hasher, body)
    }
}

bulk_client_put :: proc(fd: c.int, cipher: ^Bulk_Cipher, path: string, buffer: []byte) -> int {
    source, err := os.open(path)
    if err != nil { return error_exit("cannot open upload", err) }
    defer _ = os.close(source)
    reply := bulk_receive(fd, cipher, buffer)
    if len(reply) == 0 { return error_exit("bulk upload disconnected") }
    if reply[0] == byte(Op.Failure) { return error_exit(string(reply[1:])) }
    if reply[0] != byte(Op.Ready) { return error_exit("invalid bulk upload reply") }
    hasher: blake3.Hasher
    blake3.init(&hasher)
    for {
        n, err := os.read(source, buffer[3:3+BULK_DATA])
        if err != nil && err != .EOF { return error_exit("cannot read upload", err) }
        if n == 0 { break }
        blake3.update(&hasher, buffer[3:3+n])
        if !bulk_send(fd, cipher, buffer, .Upload, buffer[3:3+n]) { return error_exit("bulk upload disconnected") }
    }
    digest := blake3.final(&hasher)
    if !bulk_send(fd, cipher, buffer, .Digest, digest[:]) { return error_exit("bulk upload disconnected") }
    reply = bulk_receive(fd, cipher, buffer)
    if len(reply) == 0 { return error_exit("bulk upload outcome is unknown") }
    if reply[0] == byte(Op.Failure) { return error_exit(string(reply[1:])) }
    return 0 if reply[0] == byte(Op.Done) else error_exit("invalid bulk upload reply")
}
