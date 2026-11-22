package eco

import "core:fmt"
import "core:os"
import "core:testing"

@(test)
trust_store_round_trip_and_rejects_malformed :: proc(t: ^testing.T) {
    a, b: [32]byte
    for i in 0..<32 { a[i], b[i] = u8(i), u8(255-i) }
    entries := [?]Trust_Entry{trust_entry(a[:], "laptop"), trust_entry(b[:], "127.0.0.1:8443", 60)}
    entries[1].revoked = true
    data := trust_encode(entries[:])
    decoded, ok := trust_decode(data)
    testing.expect(t, ok)
    testing.expect_value(t, len(decoded), 2)
    testing.expect_value(t, decoded[0], entries[0])
    testing.expect_value(t, decoded[1], entries[1])
    testing.expect_value(t, decoded[1].expires_at, decoded[1].added_at+60)

    // Any change to the bytes, a truncation, or a text list of keys authorizes nothing.
    for offset in ([?]int{0, 8, 12, TRUST_HEADER, TRUST_HEADER+48, TRUST_HEADER+49, len(data)-1}) {
        corrupt := make([]byte, len(data), context.temp_allocator)
        copy(corrupt, data)
        corrupt[offset] ~= 0x40
        _, valid := trust_decode(corrupt)
        testing.expectf(t, !valid, "byte %d flipped", offset)
    }
    _, truncated := trust_decode(data[:len(data)-1])
    testing.expect(t, !truncated)
    text := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f laptop\n"
    _, parsed := trust_decode(transmute([]byte)text)
    testing.expect(t, !parsed)
}

@(test)
trust_entry_state :: proc(t: ^testing.T) {
    key: [32]byte = 7
    entry := trust_entry(key[:], "bad name/../\x00")
    testing.expect_value(t, trust_label(&entry), "badname..")
    now := entry.added_at
    testing.expect(t, trust_active(&entry, now))
    entry.expires_at = now+1
    testing.expect(t, trust_active(&entry, now))
    testing.expect(t, !trust_active(&entry, now+1))
    entry.expires_at = 0
    entry.revoked = true
    testing.expect(t, !trust_active(&entry, now))
}

@(test)
trust_store_file_updates :: proc(t: ^testing.T) {
    directory, err := os.make_directory_temp("", "eco-trust-*", context.temp_allocator)
    testing.expect(t, err == nil)
    defer _ = os.remove_all(directory)
    path := fmt.tprintf("%s/servers", directory)
    old, new_key, other: [32]byte = 1, 2, 3
    found: [32]byte
    testing.expect(t, !trust_find_label(path, "127.0.0.1:8443", found[:]))

    // Pairing again at an address replaces the server key stored for it.
    testing.expect(t, trust_put(path, trust_entry(old[:], "127.0.0.1:8443"), true))
    testing.expect(t, trust_put(path, trust_entry(other[:], "[::1]:8443"), true))
    testing.expect(t, trust_put(path, trust_entry(new_key[:], "127.0.0.1:8443"), true))
    testing.expect(t, trust_find_label(path, "127.0.0.1:8443", found[:]))
    testing.expect_value(t, found, new_key)
    entries, ok := trust_load(path)
    testing.expect(t, ok)
    testing.expect_value(t, len(entries), 2)
    testing.expect(t, trust_permits(path, other[:]))
    testing.expect(t, !trust_permits(path, old[:]))

    // A client paired again keeps one entry, and a revoked or expired one permits nothing.
    testing.expect(t, trust_put(path, trust_entry(other[:], "renamed"), false))
    entries, ok = trust_load(path)
    testing.expect_value(t, len(entries), 2)
    entries[1].revoked = true
    testing.expect(t, trust_save(path, entries))
    testing.expect(t, !trust_permits(path, other[:]))
    expired := trust_entry(other[:], "renamed")
    expired.expires_at = expired.added_at
    testing.expect(t, trust_put(path, expired, false))
    testing.expect(t, !trust_permits(path, other[:]))
}
