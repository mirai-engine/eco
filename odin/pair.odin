package eco

import "core:crypto"
import "core:crypto/ecdh"
import "core:crypto/noise"
import "core:encoding/hex"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"
import "deps:blake3"

// Pairing uses XX because neither side knows the other's static key yet. The code shown on both
// screens is derived from the handshake transcript, which binds both static and ephemeral keys,
// so a machine in the middle makes the two codes differ.
PAIR_SUITE :: "Noise_XX_25519_ChaChaPoly_BLAKE2s"
PAIR_FIRST :: HEADER_SIZE+32
PAIR_REPLY :: HEADER_SIZE+96
PAIR_WAIT :: 5*time.Minute
PAIR_HANDSHAKE :: 5*time.Second
PAIR_LINGER :: 10*time.Second
PAIR_FAILURES :: 5
PAIR_LABEL_MAX :: 64
TRUST_FILE_MAX :: 1 << 20

Pair_Status :: enum u8 { Pending, Approved, Denied }

Pair_Answer :: enum i32 { None, Yes, No, Other }

Pairing :: struct {
    id, send_number: u64,
    remote: net.Endpoint,
    handshake: noise.Handshake_State,
    cipher: noise.Cipher_States,
    first: [PAIR_FIRST]byte,
    reply: [PAIR_REPLY]byte,
    final: [MAX_PACKET]byte,
    final_len, label_len, failures: int,
    client: [32]byte,
    label: [PAIR_LABEL_MAX]byte,
    code: [9]byte,
    started, resolved: time.Tick,
    active, completed: bool,
    status: Pair_Status,
    // Written by the console thread, consumed by the server loop.
    answer: i32,
}

eco_home :: proc() -> string {
    home := os.get_env("ECO_ODIN_HOME", context.temp_allocator)
    if home == "" {
        directory, err := os.user_home_dir(context.temp_allocator)
        if err != nil { return "" }
        home = fmt.tprintf("%s/.eco-odin", directory)
    }
    _ = os.mkdir(home, {.Read_User, .Write_User, .Execute_User})
    return home
}

known_servers_path :: proc() -> string {
    home := eco_home()
    return "" if home == "" else fmt.tprintf("%s/known_servers", home)
}

// Trust files hold one entry per line; the first field is the entry's name.
trust_fields :: proc(line: string) -> (first, second: string) {
    text := strings.trim_space(line)
    space := strings.index_any(text, " \t")
    if space < 0 { return text, "" }
    return text[:space], strings.trim_space(text[space+1:])
}

read_trust :: proc(path: string) -> (string, bool) {
    data, err := os.read_entire_file_from_path(path, context.temp_allocator)
    if err == .Not_Exist { return "", true }
    if err != nil || len(data) > TRUST_FILE_MAX { return "", false }
    return string(data), true
}

client_authorized :: proc(path: string, key: ^ecdh.Public_Key) -> bool {
    text, ok := read_trust(path)
    if !ok { return false }
    expected: [32]byte
    ecdh.public_key_bytes(key, expected[:])
    for line in strings.split_lines_iterator(&text) {
        first, _ := trust_fields(line)
        listed: [32]byte
        if decode_key(first, listed[:]) && crypto.compare_constant_time(listed[:], expected[:]) == 1 {
            return true
        }
    }
    return false
}

known_server :: proc(address: string, key: []byte) -> bool {
    path := known_servers_path()
    if path == "" { return false }
    text, ok := read_trust(path)
    if !ok { return false }
    for line in strings.split_lines_iterator(&text) {
        first, second := trust_fields(line)
        if first == address { return decode_key(second, key) }
    }
    return false
}

// ECO_ODIN_PEER pins the server key; otherwise the key that pair stored for the address is used.
client_peer :: proc(address: string) -> string {
    if peer := os.get_env("ECO_ODIN_PEER", context.temp_allocator); peer != "" { return peer }
    key: [32]byte
    if address == "" || !known_server(address, key[:]) { return "" }
    return string(hex.encode(key[:], context.temp_allocator))
}

// Replaces the entry named first, or appends it, through a private file renamed over the old one.
store_trust :: proc(path, first, line: string) -> bool {
    text, ok := read_trust(path)
    if !ok { return false }
    output: strings.Builder
    strings.builder_init(&output, context.temp_allocator)
    for existing in strings.split_lines_iterator(&text) {
        name, _ := trust_fields(existing)
        if name == "" || name == first { continue }
        strings.write_string(&output, strings.trim_space(existing))
        strings.write_byte(&output, '\n')
    }
    strings.write_string(&output, line)
    strings.write_byte(&output, '\n')
    random: [8]byte
    random_bytes(random[:])
    temp := fmt.tprintf("%s.tmp-%s", path, string(hex.encode(random[:], context.temp_allocator)))
    if !create_seed(temp, output.buf[:]) { return false }
    if os.rename(temp, path) != nil {
        _ = os.remove(temp)
        return false
    }
    return true
}

// The label is chosen by the client, so it is shown and stored only in a restricted alphabet.
clean_label :: proc(text: []byte, out: []byte) -> int {
    n := 0
    for b in text {
        if n == len(out) { break }
        switch b {
        case 'a'..='z', 'A'..='Z', '0'..='9', '.', '_', '-': out[n] = b; n += 1
        }
    }
    if n == 0 { n = copy(out, "client") }
    return n
}

pair_code :: proc(transcript: []byte) -> (code: [9]byte) {
    buffer: [64]byte
    domain :: "ECO2 pairing code"
    copy(buffer[:], domain)
    n := len(domain) + copy(buffer[len(domain):], transcript)
    digest := blake3.hash(buffer[:n])
    value := get_u64(digest[:]) % 100_000_000
    _ = fmt.bprintf(code[:], "%04d-%04d", value/10_000, value%10_000)
    return
}

pair_console :: proc(data: rawptr) {
    pairing := cast(^Pairing)data
    buffer: [256]byte
    used := 0
    for {
        n, err := os.read(os.stdin, buffer[used:])
        if err != nil || n <= 0 { return }
        used += n
        for {
            newline := strings.index_byte(string(buffer[:used]), '\n')
            if newline < 0 { break }
            word := strings.trim_space(string(buffer[:newline]))
            answer := Pair_Answer.Other
            if strings.equal_fold(word, "y") || strings.equal_fold(word, "yes") { answer = .Yes }
            if strings.equal_fold(word, "n") || strings.equal_fold(word, "no") { answer = .No }
            sync.atomic_store(&pairing.answer, i32(answer))
            copy(buffer[:], buffer[newline+1:used])
            used -= newline+1
        }
        if used == len(buffer) { used = 0 }
    }
}

start_pair_console :: proc(pairing: ^Pairing) -> bool {
    return thread.create_and_start_with_data(pairing, pair_console, self_cleanup = true) != nil
}

reset_pairing :: proc(p: ^Pairing) {
    noise.handshake_reset(&p.handshake)
    noise.cipherstates_reset(&p.cipher)
    failures := p.failures
    p^ = {}
    p.failures = failures
}

send_pair_status :: proc(udp: net.UDP_Socket, p: ^Pairing) {
    p.send_number += 1
    packet: [HEADER_SIZE+1+noise.TAG_SIZE]byte
    write_header(packet[:], .Pair_Reply, p.id, p.send_number)
    status := [1]byte{u8(p.status)}
    if noise.cipherstates_set_n(&p.cipher, true, p.send_number) != .Ok { return }
    if _, sealed := noise.seal_message(&p.cipher, packet[:HEADER_SIZE], status[:], packet[HEADER_SIZE:]); sealed != .Ok {
        return
    }
    _, _ = net.send_udp(udp, packet[:], p.remote)
}

print_pair_prompt :: proc(p: ^Pairing) {
    fmt.printfln("eco-odin: pairing request from %s at %v with code %s. Approve? [y/n]",
                 string(p.label[:p.label_len]), net.endpoint_to_string(p.remote, context.temp_allocator),
                 string(p.code[:]))
}

receive_pair :: proc(server: ^Server, packet: []byte, header: Record, from: net.Endpoint) {
    p := server.pairing
    if header.nonce == 0 {
        if len(packet) != PAIR_FIRST { return }
        if p.active {
            if p.id == header.id && !p.completed && same_endpoint(from, p.remote) &&
               string(packet) == string(p.first[:]) {
                _, _ = net.send_udp(server.udp, p.reply[:], from)
                return
            }
            // A resolved request lingers only to report its outcome; a new one replaces it.
            if !p.completed || p.status == .Pending { return }
        }
        if p.failures >= PAIR_FAILURES { return }
        reset_pairing(p)
        if noise.handshake_init(&p.handshake, false, packet[:16], &server.own, nil, PAIR_SUITE) != .Ok { return }
        empty: [1]byte
        if _, status := noise.handshake_read_message(&p.handshake, packet[HEADER_SIZE:], empty[:]); status != .Handshake_Pending {
            reset_pairing(p)
            return
        }
        write_header(p.reply[:], .Pair_Reply, header.id, 0)
        reply, status := noise.handshake_write_message(&p.handshake, nil, p.reply[HEADER_SIZE:])
        if status != .Handshake_Pending || len(reply) != PAIR_REPLY-HEADER_SIZE {
            reset_pairing(p)
            return
        }
        copy(p.first[:], packet)
        p.id, p.remote, p.started, p.active = header.id, from, time.tick_now(), true
        _, _ = net.send_udp(server.udp, p.reply[:], from)
        return
    }
    if header.nonce != 1 || !p.active || p.id != header.id || !same_endpoint(from, p.remote) { return }
    if p.completed {
        // The client resends its final message to ask for the outcome.
        if string(packet) == string(p.final[:p.final_len]) { send_pair_status(server.udp, p) }
        return
    }
    // A failed Noise read mutates the state, so validate candidates on a copy.
    candidate := p.handshake
    label: [PAIR_LABEL_MAX]byte
    payload, status := noise.handshake_read_message(&candidate, packet[HEADER_SIZE:], label[:])
    if status != .Handshake_Complete || noise.handshake_split(&candidate, &p.cipher) != .Ok {
        noise.handshake_reset(&candidate)
        return
    }
    transcript, hashed := noise.handshake_hash(&candidate)
    if hashed != .Ok {
        noise.handshake_reset(&candidate)
        return
    }
    p.code = pair_code(transcript)
    ecdh.public_key_bytes(&candidate.rs, p.client[:])
    noise.handshake_reset(&candidate)
    noise.handshake_reset(&p.handshake)
    p.label_len = clean_label(payload, p.label[:])
    p.final_len = copy(p.final[:], packet)
    p.completed, p.started = true, time.tick_now()
    _ = sync.atomic_exchange(&p.answer, i32(Pair_Answer.None))
    print_pair_prompt(p)
    send_pair_status(server.udp, p)
}

tick_pair :: proc(server: ^Server) {
    p := server.pairing
    if !p.active { return }
    if !p.completed {
        if time.tick_since(p.started) >= PAIR_HANDSHAKE { reset_pairing(p) }
        return
    }
    if p.status != .Pending {
        if time.tick_since(p.resolved) >= PAIR_LINGER { reset_pairing(p) }
        return
    }
    answer := Pair_Answer(sync.atomic_exchange(&p.answer, i32(Pair_Answer.None)))
    switch {
    case answer == .Yes:
        client := string(hex.encode(p.client[:], context.temp_allocator))
        line := fmt.tprintf("%s %s", client, string(p.label[:p.label_len]))
        if store_trust(server.clients, client, line) {
            p.status = .Approved
            fmt.printfln("eco-odin: paired %s", string(p.label[:p.label_len]))
        } else {
            p.status = .Denied
            fmt.eprintln("eco-odin: cannot store the client in", server.clients)
        }
    case answer == .No:
        p.status = .Denied
        p.failures += 1
        fmt.println("eco-odin: pairing denied")
    case answer == .Other:
        fmt.println("eco-odin: answer y or n")
    case time.tick_since(p.started) >= PAIR_WAIT:
        p.status = .Denied
        p.failures += 1
        fmt.println("eco-odin: pairing request timed out")
    }
    if p.status != .Pending {
        p.resolved = time.tick_now()
        if p.failures >= PAIR_FAILURES { fmt.println("eco-odin: pairing locked until the server restarts") }
    }
}

pair_client :: proc(address: string, name: string) -> int {
    endpoint, ok := net.parse_endpoint(address)
    if !ok || endpoint.port <= 0 || endpoint.port > 65535 { return error_exit("expected a numeric IP:port") }
    own: ecdh.Private_Key
    defer ecdh.private_key_clear(&own)
    seed: [32]byte
    key_path := os.get_env("ECO_ODIN_KEY", context.temp_allocator)
    loaded := read_private_seed(key_path, seed[:]) && ecdh.private_key_set_bytes(&own, .X25519, seed[:])
    crypto.zero_explicit(&seed, len(seed))
    if !loaded { return error_exit("set ECO_ODIN_KEY to a private key file created by keygen") }
    known := known_servers_path()
    if known == "" { return error_exit("cannot locate the home directory; set ECO_ODIN_HOME") }

    udp, err := net.make_unbound_udp_socket(family(endpoint))
    if err != nil { return error_exit("cannot open UDP", err) }
    udp_fd := eco_socket_fd(uintptr(udp))
    if udp_fd < 0 { net.close(udp); return error_exit("cannot register UDP socket") }
    defer _ = eco_close(udp_fd)
    if eco_fd_setup(udp_fd, 1) < 0 { return error_exit("cannot configure UDP socket") }

    sid: [8]byte
    random_bytes(sid[:])
    id := get_u64(sid[:]) | 1
    first: [PAIR_FIRST]byte
    write_header(first[:], .Pair, id, 0)
    handshake: noise.Handshake_State
    defer noise.handshake_reset(&handshake)
    if noise.handshake_init(&handshake, true, first[:16], &own, nil, PAIR_SUITE) != .Ok {
        return error_exit("cannot start pairing")
    }
    if _, status := noise.handshake_write_message(&handshake, nil, first[HEADER_SIZE:]); status != .Handshake_Pending {
        return error_exit("cannot start pairing")
    }

    packet: [MAX_PACKET+1]byte
    replied := false
    retry: time.Tick
    start := time.tick_now()
    for !replied && time.tick_since(start) < PAIR_HANDSHAKE && eco_stopping() == 0 {
        if retry == {} || time.tick_since(retry) >= 250*time.Millisecond {
            _, _ = net.send_udp(udp, first[:], endpoint)
            retry = time.tick_now()
        }
        if eco_wait(udp_fd, 100) == 0 { continue }
        n, from, recv_err := net.recv_udp(udp, packet[:])
        if recv_err != nil || !same_endpoint(from, endpoint) || n != PAIR_REPLY { continue }
        header, valid := parse_header(packet[:n])
        if !valid || header.kind != .Pair_Reply || header.id != id || header.nonce != 0 { continue }
        candidate := handshake
        empty: [1]byte
        if _, status := noise.handshake_read_message(&candidate, packet[HEADER_SIZE:n], empty[:]); status == .Handshake_Pending {
            noise.handshake_reset(&handshake)
            handshake = candidate
            replied = true
        } else {
            noise.handshake_reset(&candidate)
        }
    }
    if !replied { return error_exit("no pairing reply; start the server with --pair") }

    label: [PAIR_LABEL_MAX]byte
    label_len := clean_label(transmute([]byte)name, label[:])
    final: [MAX_PACKET]byte
    write_header(final[:], .Pair, id, 1)
    message, status := noise.handshake_write_message(&handshake, label[:label_len], final[HEADER_SIZE:])
    if status != .Handshake_Complete { return error_exit("pairing handshake failed") }
    final_len := HEADER_SIZE+len(message)
    cipher: noise.Cipher_States
    defer noise.cipherstates_reset(&cipher)
    if noise.handshake_split(&handshake, &cipher) != .Ok { return error_exit("pairing handshake failed") }
    transcript, hashed := noise.handshake_hash(&handshake)
    if hashed != .Ok { return error_exit("pairing handshake failed") }
    code := pair_code(transcript)
    server_key: [32]byte
    ecdh.public_key_bytes(&handshake.rs, server_key[:])
    fmt.printfln("verification code %s; approve it on the server if it shows the same code", string(code[:]))

    last: u64
    retry = {}
    start = time.tick_now()
    for time.tick_since(start) < PAIR_WAIT+PAIR_HANDSHAKE && eco_stopping() == 0 {
        if retry == {} || time.tick_since(retry) >= 500*time.Millisecond {
            _, _ = net.send_udp(udp, final[:final_len], endpoint)
            retry = time.tick_now()
        }
        if eco_wait(udp_fd, 100) == 0 { continue }
        n, from, recv_err := net.recv_udp(udp, packet[:])
        if recv_err != nil || !same_endpoint(from, endpoint) || n != HEADER_SIZE+1+noise.TAG_SIZE { continue }
        header, valid := parse_header(packet[:n])
        if !valid || header.kind != .Pair_Reply || header.id != id || header.nonce <= last { continue }
        if noise.cipherstates_set_n(&cipher, false, header.nonce) != .Ok { continue }
        plain: [1]byte
        if _, opened := noise.open_message(&cipher, packet[:HEADER_SIZE], packet[HEADER_SIZE:n], plain[:]); opened != .Ok {
            continue
        }
        last = header.nonce
        switch Pair_Status(plain[0]) {
        case .Pending:
        case .Approved:
            key := string(hex.encode(server_key[:], context.temp_allocator))
            if !store_trust(known, address, fmt.tprintf("%s %s", address, key)) {
                return error_exit("cannot store the server in", known)
            }
            fmt.printfln("paired with %s, server key %s", address, key)
            return 0
        case .Denied:
            return error_exit("pairing denied, timed out or locked on the server")
        case:
            return error_exit("invalid pairing reply")
        }
    }
    if eco_stopping() != 0 { return 130 }
    return error_exit("pairing timed out")
}
