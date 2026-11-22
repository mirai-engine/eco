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

// Pairing runs Noise XX because neither side knows the other's static key yet. The initiator
// commits to its static key and a fresh nonce N_I in the first message and opens the commitment
// only in the third, after the responder has revealed its own nonce N_R. The verification code
// hashes both ephemeral and static keys and both nonces, and nothing either side can choose
// after seeing the other's nonce, so a machine in the middle that runs one handshake with each
// side matches the two codes with probability 10^-8 per attempt instead of grinding a label.
PAIR_SUITE :: "Noise_XX_25519_ChaChaPoly_BLAKE2s"
PAIR_COMMIT_DOMAIN :: "eco-pair-commit-v2"
PAIR_CODE_DOMAIN :: "eco-pair-code-v2"
PAIR_NONCE :: 32
PAIR_LABEL_MAX :: TRUST_LABEL_MAX
// P1: e_I and the commitment, in clear.
PAIR_FIRST :: HEADER_SIZE+32+32
// P2: e_R, the encrypted s_R and the encrypted N_R and responder name.
PAIR_REPLY_MIN :: HEADER_SIZE+32+32+noise.TAG_SIZE+PAIR_NONCE+1+noise.TAG_SIZE
PAIR_REPLY_MAX :: PAIR_REPLY_MIN-1+PAIR_LABEL_MAX
// P3: the encrypted s_I and the encrypted N_I and initiator name.
PAIR_FINAL_MIN :: HEADER_SIZE+32+noise.TAG_SIZE+PAIR_NONCE+1+noise.TAG_SIZE
PAIR_FINAL_MAX :: PAIR_FINAL_MIN-1+PAIR_LABEL_MAX
PAIR_WAIT :: 5*time.Minute
PAIR_HANDSHAKE :: 5*time.Second
PAIR_LINGER :: 10*time.Second
PAIR_FAILURES :: 5
PAIR_COOLDOWN :: 10*time.Minute

Pair_Status :: enum u8 { Pending, Approved, Denied }

Pair_Answer :: enum i64 { None, Yes, No, Other }

Pair_Check :: enum { Ok, Invalid, Mismatch }

Pairing :: struct {
    id, send_number: u64,
    remote: net.Endpoint,
    handshake: noise.Handshake_State,
    cipher: noise.Cipher_States,
    first: [PAIR_FIRST]byte,
    reply: [PAIR_REPLY_MAX]byte,
    final: [PAIR_FINAL_MAX]byte,
    commit, nonce: [32]byte,
    reply_len, final_len, label_len, name_len, title_len, failures: int,
    client: [32]byte,
    label, name: [PAIR_LABEL_MAX]byte,
    code: [9]byte,
    title: [32]byte,
    started, resolved, locked: time.Tick,
    active, completed: bool,
    status: Pair_Status,
    // Numbers each completed request; approval threads read it atomically.
    serial: i64,
    // serial << 8 | Pair_Answer, written by an approval thread and consumed by the server loop,
    // so an answer to an expired request never approves a later one.
    answer: i64,
}

Pair_Prompt :: struct {
    pairing: ^Pairing,
    serial: i64,
    title: [32]byte,
    text: [256]byte,
    title_len, text_len: int,
}

machine_name :: proc() -> string {
    return os.get_env("COMPUTERNAME" when ODIN_OS == .Windows else "HOSTNAME", context.temp_allocator)
}

pair_commitment :: proc(static_key, nonce: []byte) -> [32]byte {
    hasher: blake3.Hasher
    blake3.init(&hasher)
    blake3.update(&hasher, transmute([]byte)string(PAIR_COMMIT_DOMAIN))
    blake3.update(&hasher, static_key)
    blake3.update(&hasher, nonce)
    return blake3.final(&hasher)
}

pair_code :: proc(e_i, e_r, s_i, s_r, n_i, n_r: []byte) -> (code: [9]byte) {
    hasher: blake3.Hasher
    blake3.init(&hasher)
    blake3.update(&hasher, transmute([]byte)string(PAIR_CODE_DOMAIN))
    for part in ([?][]byte{e_i, e_r, s_i, s_r, n_i, n_r}) { blake3.update(&hasher, part) }
    digest := blake3.final(&hasher)
    value := get_u64(digest[:]) % 100_000_000
    _ = fmt.bprintf(code[:], "%04d-%04d", value/10_000, value%10_000)
    return
}

// The code of a completed handshake, the same on both sides.
pair_session_code :: proc(hs: ^noise.Handshake_State, n_i, n_r: []byte) -> [9]byte {
    own_e, own_s, peer_e, peer_s: [32]byte
    ecdh.private_key_public_bytes(&hs.e, own_e[:])
    ecdh.private_key_public_bytes(&hs.s, own_s[:])
    ecdh.public_key_bytes(&hs.re, peer_e[:])
    ecdh.public_key_bytes(&hs.rs, peer_s[:])
    if hs.initiator { return pair_code(own_e[:], peer_e[:], own_s[:], peer_s[:], n_i, n_r) }
    return pair_code(peer_e[:], own_e[:], peer_s[:], own_s[:], n_i, n_r)
}

pair_write_first :: proc(hs: ^noise.Handshake_State, n_i, dst: []byte) -> ([]byte, bool) {
    s_i: [32]byte
    ecdh.private_key_public_bytes(&hs.s, s_i[:])
    commit := pair_commitment(s_i[:], n_i)
    message, status := noise.handshake_write_message(hs, commit[:], dst)
    return message, status == .Handshake_Pending
}

pair_read_first :: proc(hs: ^noise.Handshake_State, message: []byte, commit: ^[32]byte) -> bool {
    payload: [33]byte
    received, status := noise.handshake_read_message(hs, message, payload[:])
    if status != .Handshake_Pending || len(received) != len(commit) { return false }
    copy(commit[:], received)
    return true
}

// P2 and P3 carry the sender's nonce followed by its name.
pair_write_nonce :: proc(hs: ^noise.Handshake_State, nonce, name, dst: []byte) -> ([]byte, noise.Status) {
    payload: [PAIR_NONCE+PAIR_LABEL_MAX]byte
    copy(payload[:], nonce)
    n := PAIR_NONCE+clean_label(name, payload[PAIR_NONCE:], "peer")
    return noise.handshake_write_message(hs, payload[:n], dst)
}

// A failed Noise read mutates the state, so both reads validate on a copy.
pair_read_nonce :: proc(hs: ^noise.Handshake_State, message: []byte, want: noise.Status,
                        nonce: ^[32]byte, name: []byte) -> (name_len: int, ok: bool) {
    candidate := hs^
    payload: [PAIR_NONCE+PAIR_LABEL_MAX]byte
    received, status := noise.handshake_read_message(&candidate, message, payload[:])
    if status != want || len(received) <= PAIR_NONCE {
        noise.handshake_reset(&candidate)
        return 0, false
    }
    noise.handshake_reset(hs)
    hs^ = candidate
    copy(nonce[:], received[:PAIR_NONCE])
    return clean_label(received[PAIR_NONCE:], name, "peer"), true
}

// The responder checks that P3 opens the commitment of P1 before it derives or shows a code.
// A mismatch keeps the completed handshake so the responder can report the denial.
pair_read_final :: proc(hs: ^noise.Handshake_State, message, commit: []byte, n_i: ^[32]byte,
                        name: []byte) -> (name_len: int, check: Pair_Check) {
    valid: bool
    name_len, valid = pair_read_nonce(hs, message, .Handshake_Complete, n_i, name)
    if !valid { return 0, .Invalid }
    s_i: [32]byte
    ecdh.public_key_bytes(&hs.rs, s_i[:])
    opened := pair_commitment(s_i[:], n_i[:])
    if crypto.compare_constant_time(opened[:], commit) != 1 { return 0, .Mismatch }
    return name_len, .Ok
}

post_pair_answer :: proc(pairing: ^Pairing, serial: i64, answer: Pair_Answer) {
    sync.atomic_store(&pairing.answer, serial << 8 | i64(answer))
}

when ODIN_OS != .Linux {
    pair_prompt_thread :: proc(data: rawptr) {
        prompt := cast(^Pair_Prompt)data
        defer free(prompt)
        answer := ask_pair_approval(string(prompt.title[:prompt.title_len]), string(prompt.text[:prompt.text_len]))
        post_pair_answer(prompt.pairing, prompt.serial, answer)
    }
}

// Linux servers have no common desktop to ask in, so the operator answers in the server's
// terminal; Windows and macOS show a dialog in the operator's session.
start_pair_approval :: proc(p: ^Pairing) -> bool {
    fmt.printfln("eco: pairing request from %s at %v with code %s%s", string(p.label[:p.label_len]),
                 net.endpoint_to_string(p.remote, context.temp_allocator), string(p.code[:]),
                 ". Approve? [y/n]" when ODIN_OS == .Linux else "")
    when ODIN_OS == .Linux {
        return true
    } else {
        text := fmt.tprintf("%s at %s wants to pair with this computer and run commands as you.\n\nCode: %s\n\nApprove only if the other screen shows the same code.",
                            string(p.label[:p.label_len]), net.endpoint_to_string(p.remote, context.temp_allocator),
                            string(p.code[:]))
        prompt := new(Pair_Prompt)
        if prompt == nil { return false }
        prompt.pairing, prompt.serial = p, p.serial
        prompt.title_len = copy(prompt.title[:], p.title[:p.title_len])
        prompt.text_len = copy(prompt.text[:], text)
        if thread.create_and_start_with_data(prompt, pair_prompt_thread, self_cleanup = true) == nil {
            free(prompt)
            return false
        }
        return true
    }
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
            post_pair_answer(pairing, sync.atomic_load(&pairing.serial), answer)
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
    failures, locked, serial, name, name_len := p.failures, p.locked, p.serial, p.name, p.name_len
    p^ = {}
    p.failures, p.locked, p.name, p.name_len = failures, locked, name, name_len
    sync.atomic_store(&p.serial, serial)
}

pair_failed :: proc(p: ^Pairing) {
    p.status, p.resolved = .Denied, time.tick_now()
    p.failures += 1
    if p.failures >= PAIR_FAILURES {
        p.locked = p.resolved
        fmt.println("eco: pairing paused for ten minutes after repeated failures")
    }
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

receive_pair :: proc(server: ^Server, packet: []byte, header: Record, from: net.Endpoint) {
    p := server.pairing
    if header.nonce == 0 {
        if len(packet) != PAIR_FIRST { return }
        if p.active {
            if p.id == header.id && !p.completed && same_endpoint(from, p.remote) &&
               string(packet) == string(p.first[:]) {
                _, _ = net.send_udp(server.udp, p.reply[:p.reply_len], from)
                return
            }
            // A resolved request lingers only to report its outcome; a new one replaces it.
            if !p.completed || p.status == .Pending { return }
        }
        if p.failures >= PAIR_FAILURES {
            if time.tick_since(p.locked) < PAIR_COOLDOWN { return }
            p.failures = 0
        }
        reset_pairing(p)
        if noise.handshake_init(&p.handshake, false, packet[:16], &server.own, nil, PAIR_SUITE) != .Ok ||
           !pair_read_first(&p.handshake, packet[HEADER_SIZE:], &p.commit) {
            reset_pairing(p)
            return
        }
        random_bytes(p.nonce[:])
        write_header(p.reply[:], .Pair_Reply, header.id, 0)
        reply, status := pair_write_nonce(&p.handshake, p.nonce[:], p.name[:p.name_len], p.reply[HEADER_SIZE:])
        if status != .Handshake_Pending {
            reset_pairing(p)
            return
        }
        copy(p.first[:], packet)
        p.reply_len = HEADER_SIZE+len(reply)
        p.id, p.remote, p.started, p.active = header.id, from, time.tick_now(), true
        _, _ = net.send_udp(server.udp, p.reply[:p.reply_len], from)
        return
    }
    if header.nonce != 1 || !p.active || p.id != header.id || !same_endpoint(from, p.remote) { return }
    if p.completed {
        // The client resends its final message to ask for the outcome.
        if string(packet) == string(p.final[:p.final_len]) { send_pair_status(server.udp, p) }
        return
    }
    if len(packet) < PAIR_FINAL_MIN || len(packet) > PAIR_FINAL_MAX { return }
    n_i: [32]byte
    label_len, check := pair_read_final(&p.handshake, packet[HEADER_SIZE:], p.commit[:], &n_i, p.label[:])
    if check == .Invalid { return }
    if noise.handshake_split(&p.handshake, &p.cipher) != .Ok {
        reset_pairing(p)
        return
    }
    p.final_len = copy(p.final[:], packet)
    p.completed, p.started = true, time.tick_now()
    if check == .Mismatch {
        noise.handshake_reset(&p.handshake)
        pair_failed(p)
        fmt.println("eco: pairing rejected because the client did not open its commitment")
        send_pair_status(server.udp, p)
        return
    }
    p.code = pair_session_code(&p.handshake, n_i[:], p.nonce[:])
    ecdh.public_key_bytes(&p.handshake.rs, p.client[:])
    noise.handshake_reset(&p.handshake)
    p.label_len = label_len
    sync.atomic_store(&p.serial, p.serial+1)
    p.title_len = len(fmt.bprintf(p.title[:], "eco pairing %s", string(p.code[:])))
    if !start_pair_approval(p) { p.status, p.resolved = .Denied, time.tick_now() }
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
    posted := sync.atomic_exchange(&p.answer, 0)
    answer := Pair_Answer(posted & 0xff) if posted >> 8 == p.serial else .None
    switch {
    case answer == .Yes:
        label := string(p.label[:p.label_len])
        p.resolved = time.tick_now()
        if trust_put(server.clients, trust_entry(p.client[:], label), false) {
            p.status, p.failures = .Approved, 0
            fmt.printfln("eco: paired %s", label)
        } else {
            p.status = .Denied
            fmt.eprintln("eco: cannot store the client in", server.clients)
        }
    case answer == .No:
        pair_failed(p)
        fmt.println("eco: pairing denied")
    case answer == .Other:
        fmt.println("eco: answer y or n")
    case time.tick_since(p.started) >= PAIR_WAIT:
        pair_failed(p)
        when ODIN_OS != .Linux { close_pair_approval(string(p.title[:p.title_len])) }
        fmt.println("eco: pairing request timed out")
    }
}

pair_client :: proc(address: string, name: string) -> int {
    endpoint, ok := net.parse_endpoint(address)
    if !ok || endpoint.port <= 0 || endpoint.port > 65535 { return error_exit("expected a numeric IP:port") }
    own: ecdh.Private_Key
    defer ecdh.private_key_clear(&own)
    seed: [32]byte
    key_path := os.get_env("ECO_KEY", context.temp_allocator)
    loaded := read_private_seed(key_path, seed[:]) && ecdh.private_key_set_bytes(&own, .X25519, seed[:])
    crypto.zero_explicit(&seed, len(seed))
    if !loaded { return error_exit("set ECO_KEY to a private key file created by keygen") }
    known := servers_path()
    if known == "" { return error_exit("cannot locate the home directory; set ECO_HOME") }

    udp, err := net.make_unbound_udp_socket(family(endpoint))
    if err != nil { return error_exit("cannot open UDP", err) }
    udp_fd := eco_socket_fd(uintptr(udp))
    if udp_fd < 0 { net.close(udp); return error_exit("cannot register UDP socket") }
    defer _ = eco_close(udp_fd)
    if eco_fd_setup(udp_fd, 1) < 0 { return error_exit("cannot configure UDP socket") }

    sid: [8]byte
    random_bytes(sid[:])
    id := get_u64(sid[:]) | 1
    n_i, n_r: [32]byte
    random_bytes(n_i[:])
    first: [PAIR_FIRST]byte
    write_header(first[:], .Pair, id, 0)
    handshake: noise.Handshake_State
    defer noise.handshake_reset(&handshake)
    if noise.handshake_init(&handshake, true, first[:16], &own, nil, PAIR_SUITE) != .Ok {
        return error_exit("cannot start pairing")
    }
    if _, written := pair_write_first(&handshake, n_i[:], first[HEADER_SIZE:]); !written {
        return error_exit("cannot start pairing")
    }

    packet: [MAX_PACKET+1]byte
    server_name: [PAIR_LABEL_MAX]byte
    server_name_len := 0
    retry: time.Tick
    start := time.tick_now()
    for server_name_len == 0 && time.tick_since(start) < PAIR_HANDSHAKE && eco_stopping() == 0 {
        if retry == {} || time.tick_since(retry) >= 250*time.Millisecond {
            _, _ = net.send_udp(udp, first[:], endpoint)
            retry = time.tick_now()
        }
        if eco_wait(udp_fd, 100) == 0 { continue }
        n, from, recv_err := net.recv_udp(udp, packet[:])
        if recv_err != nil || !same_endpoint(from, endpoint) || n < PAIR_REPLY_MIN || n > PAIR_REPLY_MAX { continue }
        header, valid := parse_header(packet[:n])
        if !valid || header.kind != .Pair_Reply || header.id != id || header.nonce != 0 { continue }
        server_name_len, _ = pair_read_nonce(&handshake, packet[HEADER_SIZE:n], .Handshake_Pending, &n_r, server_name[:])
    }
    if server_name_len == 0 { return error_exit("no pairing reply; check the address, that the server runs and that its firewall admits UDP") }

    final: [PAIR_FINAL_MAX]byte
    write_header(final[:], .Pair, id, 1)
    message, status := pair_write_nonce(&handshake, n_i[:], transmute([]byte)name, final[HEADER_SIZE:])
    if status != .Handshake_Complete { return error_exit("pairing handshake failed") }
    final_len := HEADER_SIZE+len(message)
    cipher: noise.Cipher_States
    defer noise.cipherstates_reset(&cipher)
    if noise.handshake_split(&handshake, &cipher) != .Ok { return error_exit("pairing handshake failed") }
    code := pair_session_code(&handshake, n_i[:], n_r[:])
    server_key: [32]byte
    ecdh.public_key_bytes(&handshake.rs, server_key[:])
    fmt.printfln("verification code %s from %s; approve it on the server if it shows the same code",
                 string(code[:]), string(server_name[:server_name_len]))

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
            if !trust_put(known, trust_entry(server_key[:], address), true) {
                return error_exit("cannot store the server in", known)
            }
            fmt.printfln("paired with %s, server key %s", address, string(hex.encode(server_key[:], context.temp_allocator)))
            return 0
        case .Denied:
            return error_exit("pairing denied, expired or paused on the server")
        case:
            return error_exit("invalid pairing reply")
        }
    }
    if eco_stopping() != 0 { return 130 }
    return error_exit("pairing timed out")
}
