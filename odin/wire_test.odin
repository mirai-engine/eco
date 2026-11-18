package eco

import "core:crypto/ecdh"
import "core:crypto/noise"
import "core:testing"

@(test)
replay_window_tests :: proc(t: ^testing.T) {
    window: Replay
    testing.expect(t, !replay_allowed(&window, 0))
    testing.expect(t, !replay_allowed(&window, RECORD_LIMIT))
    testing.expect(t, replay_allowed(&window, 3))
    replay_commit(&window, 3)
    testing.expect(t, !replay_allowed(&window, 3))
    testing.expect(t, replay_allowed(&window, 2))
    replay_commit(&window, 2)
    replay_commit(&window, REPLAY_WINDOW+3)
    testing.expect(t, !replay_allowed(&window, 3))
    testing.expect(t, replay_allowed(&window, 4))
    testing.expect(t, !replay_allowed(&window, REPLAY_WINDOW+3))
}

@(test)
record_auth_and_order_tests :: proc(t: ^testing.T) {
    client, server: ecdh.Private_Key
    defer ecdh.private_key_clear(&client)
    defer ecdh.private_key_clear(&server)
    testing.expect(t, ecdh.private_key_generate(&client, .X25519))
    testing.expect(t, ecdh.private_key_generate(&server, .X25519))
    peer: ecdh.Public_Key
    ecdh.public_key_set_priv(&peer, &server)
    initiator, responder: noise.Handshake_State
    defer noise.handshake_reset(&initiator)
    defer noise.handshake_reset(&responder)
    prologue := []byte{0x45, 0x43, 0x4f, 0x32}
    testing.expect_value(t, noise.handshake_init(&initiator, true, prologue, &client, &peer, NOISE_SUITE), .Ok)
    testing.expect_value(t, noise.handshake_init(&responder, false, prologue, &server, nil, NOISE_SUITE), .Ok)
    handshake: [128]byte
    payload: [1]byte
    hello, pending := noise.handshake_write_message(&initiator, []byte{0}, handshake[:])
    testing.expect_value(t, pending, .Handshake_Pending)
    _, accepted := noise.handshake_read_message(&responder, hello, payload[:])
    testing.expect_value(t, accepted, .Handshake_Pending)
    welcome, completed := noise.handshake_write_message(&responder, payload[:], handshake[:])
    testing.expect_value(t, completed, .Handshake_Complete)
    _, complete := noise.handshake_read_message(&initiator, welcome, payload[:])
    testing.expect_value(t, complete, .Handshake_Complete)
    outgoing, incoming: Link
    defer reset_link(&outgoing)
    defer reset_link(&incoming)
    outgoing.id = 39
    testing.expect_value(t, noise.handshake_split(&initiator, &outgoing.cipher), .Ok)
    testing.expect_value(t, noise.handshake_split(&responder, &incoming.cipher), .Ok)

    send_first, send_second, dst: [MAX_PACKET]byte
    first := seal(&outgoing, .Data, []byte{1}, send_first[:])
    second := seal(&outgoing, .Data, []byte{2}, send_second[:])
    h2, ok := parse_header(second)
    testing.expect(t, ok)
    testing.expect_value(t, h2.id, u64(39))
    second[len(second)-1] = second[len(second)-1] ~ 1
    _, valid := unseal(&incoming, h2, second, dst[:])
    testing.expect(t, !valid)
    second[len(second)-1] = second[len(second)-1] ~ 1
    contents: []byte
    contents, valid = unseal(&incoming, h2, second, dst[:])
    testing.expect(t, valid && len(contents) == 1 && contents[0] == 2)
    h1, parsed := parse_header(first)
    testing.expect(t, parsed)
    contents, valid = unseal(&incoming, h1, first, dst[:])
    testing.expect(t, valid && len(contents) == 1 && contents[0] == 1)
    _, valid = unseal(&incoming, h1, first, dst[:])
    testing.expect(t, !valid)
}

@(test)
identity_comparison_test :: proc(t: ^testing.T) {
    a, b: ecdh.Private_Key
    defer ecdh.private_key_clear(&a)
    defer ecdh.private_key_clear(&b)
    testing.expect(t, ecdh.private_key_generate(&a, .X25519))
    testing.expect(t, ecdh.private_key_generate(&b, .X25519))
    p, q: ecdh.Public_Key
    ecdh.public_key_set_priv(&p, &a)
    ecdh.public_key_set_priv(&q, &b)
    p_bytes, q_bytes: [32]byte
    ecdh.public_key_bytes(&p, p_bytes[:])
    ecdh.public_key_bytes(&q, q_bytes[:])
    testing.expect(t, p_bytes != q_bytes)
    testing.expect(t, !ecdh.public_key_equal(&p, &q))
}
