package eco

import "core:testing"

@(test)
bulk_cipher_directions :: proc(t: ^testing.T) {
    transcript, seed: [32]byte = 3, 5
    client, server: Bulk_Cipher
    bulk_cipher_init(&client, transcript[:], seed[:], true)
    bulk_cipher_init(&server, transcript[:], seed[:], false)
    defer bulk_cipher_free(&client)
    defer bulk_cipher_free(&server)

    aad := [2]byte{1, 2}
    for round in 0..<3 {
        plain: [64]byte = u8(round)
        text := plain
        tag: [BULK_TAG]byte
        testing.expect(t, bulk_crypt(&client.send, aad[:], text[:], tag[:], true))
        testing.expect(t, text != plain)
        testing.expect(t, bulk_crypt(&server.receive, aad[:], text[:], tag[:], false))
        testing.expect_value(t, text, plain)
    }

    // A record opens only under its direction's key and its position in the stream.
    text: [16]byte = 9
    tag: [BULK_TAG]byte
    testing.expect(t, bulk_crypt(&server.send, aad[:], text[:], tag[:], true))
    sealed := text
    testing.expect(t, !bulk_crypt(&server.receive, aad[:], text[:], tag[:], false))
    text = sealed
    skipped := client.receive
    skipped.counter += 1
    testing.expect(t, !bulk_crypt(&skipped, aad[:], text[:], tag[:], false))
    text = sealed
    testing.expect(t, bulk_crypt(&client.receive, aad[:], text[:], tag[:], false))
}
