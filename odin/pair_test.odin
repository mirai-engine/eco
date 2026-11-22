package eco

import "core:crypto/ecdh"
import "core:crypto/noise"
import "core:strings"
import "core:testing"

Pair_Fixture :: struct {
    s_i, s_r, e_i, e_r: ecdh.Private_Key,
    n_i, n_r: [32]byte,
}

pair_fixture :: proc(t: ^testing.T, f: ^Pair_Fixture) {
    seeds: [4][32]byte
    for &seed, i in seeds { for &b, j in seed { b = u8(i*41 + j*7 + 1) } }
    keys := [4]^ecdh.Private_Key{&f.s_i, &f.s_r, &f.e_i, &f.e_r}
    for key, i in keys { testing.expect(t, ecdh.private_key_set_bytes(key, .X25519, seeds[i][:])) }
    for &b, i in f.n_i { b = u8(200 - i) }
    for &b, i in f.n_r { b = u8(i * 3) }
}

pair_fixture_clear :: proc(f: ^Pair_Fixture) {
    for key in ([4]^ecdh.Private_Key{&f.s_i, &f.s_r, &f.e_i, &f.e_r}) { ecdh.private_key_clear(key) }
}

Pair_Run :: struct {
    code_i, code_r: [9]byte,
    check: Pair_Check,
    name_i, name_r: string,
}

// Runs P1, P2 and P3 in memory. open_nonce is the N_I that P3 reveals, normally the committed one.
pair_run :: proc(t: ^testing.T, f: ^Pair_Fixture, name_i, name_r: string, open_nonce: []byte) -> (run: Pair_Run) {
    prologue := "pairing test prologue"
    initiator, responder: noise.Handshake_State
    defer noise.handshake_reset(&initiator)
    defer noise.handshake_reset(&responder)
    testing.expect_value(t, noise.handshake_init(&initiator, true, transmute([]byte)prologue, &f.s_i, nil,
                                                 PAIR_SUITE, _e = &f.e_i), noise.Status.Ok)
    testing.expect_value(t, noise.handshake_init(&responder, false, transmute([]byte)prologue, &f.s_r, nil,
                                                 PAIR_SUITE, _e = &f.e_r), noise.Status.Ok)

    first: [PAIR_FIRST-HEADER_SIZE]byte
    p1, written := pair_write_first(&initiator, f.n_i[:], first[:])
    testing.expect(t, written)
    commit: [32]byte
    testing.expect(t, pair_read_first(&responder, p1, &commit))

    reply: [PAIR_REPLY_MAX-HEADER_SIZE]byte
    p2, status := pair_write_nonce(&responder, f.n_r[:], transmute([]byte)name_r, reply[:])
    testing.expect_value(t, status, noise.Status.Handshake_Pending)
    n_r: [32]byte
    server: [PAIR_LABEL_MAX]byte
    server_len, read := pair_read_nonce(&initiator, p2, .Handshake_Pending, &n_r, server[:])
    testing.expect(t, read)
    testing.expect_value(t, n_r, f.n_r)

    final: [PAIR_FINAL_MAX-HEADER_SIZE]byte
    p3: []byte
    p3, status = pair_write_nonce(&initiator, open_nonce, transmute([]byte)name_i, final[:])
    testing.expect_value(t, status, noise.Status.Handshake_Complete)
    n_i: [32]byte
    client: [PAIR_LABEL_MAX]byte
    client_len: int
    client_len, run.check = pair_read_final(&responder, p3, commit[:], &n_i, client[:])
    run.code_i = pair_session_code(&initiator, f.n_i[:], n_r[:])
    if run.check == .Ok { run.code_r = pair_session_code(&responder, n_i[:], f.n_r[:]) }
    run.name_i = strings.clone(string(client[:client_len]), context.temp_allocator)
    run.name_r = strings.clone(string(server[:server_len]), context.temp_allocator)
    return
}

@(test)
pairing_codes_match_and_ignore_names :: proc(t: ^testing.T) {
    f: Pair_Fixture
    pair_fixture(t, &f)
    defer pair_fixture_clear(&f)

    first := pair_run(t, &f, "laptop", "server", f.n_i[:])
    testing.expect_value(t, first.check, Pair_Check.Ok)
    testing.expect_value(t, first.code_i, first.code_r)
    testing.expect_value(t, first.name_i, "laptop")
    testing.expect_value(t, first.name_r, "server")
    testing.expect_value(t, first.code_i[4], u8('-'))

    // A name in P2 or P3 changes the transcript hash, but not the code.
    for names in ([?][2]string{{"laptop-0000001", "server"}, {"laptop", "x"}, {"zzzz", "server-renamed"}}) {
        renamed := pair_run(t, &f, names[0], names[1], f.n_i[:])
        testing.expect_value(t, renamed.check, Pair_Check.Ok)
        testing.expect_value(t, renamed.code_i, first.code_i)
        testing.expect_value(t, renamed.code_r, first.code_r)
    }

    // Every key and nonce feeds the code.
    keys := pair_code_inputs(&f)
    base := pair_code(keys[0][:], keys[1][:], keys[2][:], keys[3][:], keys[4][:], keys[5][:])
    testing.expect_value(t, base, first.code_i)
    for i in 0..<len(keys) {
        changed := keys
        changed[i][31] ~= 1
        code := pair_code(changed[0][:], changed[1][:], changed[2][:], changed[3][:], changed[4][:], changed[5][:])
        testing.expectf(t, code != base, "input %d does not change the code", i)
    }
}

pair_code_inputs :: proc(f: ^Pair_Fixture) -> (keys: [6][32]byte) {
    ecdh.private_key_public_bytes(&f.e_i, keys[0][:])
    ecdh.private_key_public_bytes(&f.e_r, keys[1][:])
    ecdh.private_key_public_bytes(&f.s_i, keys[2][:])
    ecdh.private_key_public_bytes(&f.s_r, keys[3][:])
    keys[4], keys[5] = f.n_i, f.n_r
    return
}

@(test)
pairing_rejects_commitment_mismatch :: proc(t: ^testing.T) {
    f: Pair_Fixture
    pair_fixture(t, &f)
    defer pair_fixture_clear(&f)

    // An initiator that learned N_R and reveals a different N_I than it committed to is rejected
    // before the responder derives a code.
    other := f.n_i
    other[0] ~= 0x80
    run := pair_run(t, &f, "laptop", "server", other[:])
    testing.expect_value(t, run.check, Pair_Check.Mismatch)
    testing.expect_value(t, run.code_r, [9]byte{})

    // A commitment to another static key does not open with the key the handshake proves.
    stranger: ecdh.Private_Key
    defer ecdh.private_key_clear(&stranger)
    seed: [32]byte = 9
    testing.expect(t, ecdh.private_key_set_bytes(&stranger, .X25519, seed[:]))
    s_stranger, s_i: [32]byte
    ecdh.private_key_public_bytes(&stranger, s_stranger[:])
    ecdh.private_key_public_bytes(&f.s_i, s_i[:])
    a, b := pair_commitment(s_stranger[:], f.n_i[:]), pair_commitment(s_i[:], f.n_i[:])
    testing.expect(t, a != b)
}

@(test)
pairing_rejects_tampered_final :: proc(t: ^testing.T) {
    f: Pair_Fixture
    pair_fixture(t, &f)
    defer pair_fixture_clear(&f)
    prologue := "pairing test prologue"
    initiator, responder: noise.Handshake_State
    defer noise.handshake_reset(&initiator)
    defer noise.handshake_reset(&responder)
    _ = noise.handshake_init(&initiator, true, transmute([]byte)prologue, &f.s_i, nil, PAIR_SUITE, _e = &f.e_i)
    _ = noise.handshake_init(&responder, false, transmute([]byte)prologue, &f.s_r, nil, PAIR_SUITE, _e = &f.e_r)
    first: [PAIR_FIRST-HEADER_SIZE]byte
    p1, _ := pair_write_first(&initiator, f.n_i[:], first[:])
    commit: [32]byte
    testing.expect(t, pair_read_first(&responder, p1, &commit))
    reply: [PAIR_REPLY_MAX-HEADER_SIZE]byte
    p2, _ := pair_write_nonce(&responder, f.n_r[:], nil, reply[:])
    n_r: [32]byte
    name: [PAIR_LABEL_MAX]byte
    _, _ = pair_read_nonce(&initiator, p2, .Handshake_Pending, &n_r, name[:])
    final: [PAIR_FINAL_MAX-HEADER_SIZE]byte
    p3, _ := pair_write_nonce(&initiator, f.n_i[:], nil, final[:])

    // A forged P3 is ignored and leaves the responder able to accept the genuine one.
    p3[len(p3)-1] ~= 1
    n_i: [32]byte
    _, check := pair_read_final(&responder, p3, commit[:], &n_i, name[:])
    testing.expect_value(t, check, Pair_Check.Invalid)
    p3[len(p3)-1] ~= 1
    _, check = pair_read_final(&responder, p3, commit[:], &n_i, name[:])
    testing.expect_value(t, check, Pair_Check.Ok)
    testing.expect_value(t, pair_session_code(&responder, n_i[:], f.n_r[:]),
                         pair_session_code(&initiator, f.n_i[:], n_r[:]))
}
