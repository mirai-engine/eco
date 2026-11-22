package eco

import "core:crypto"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:time"
import "deps:blake3"

// A trust store is TRUST_MAGIC, a little-endian u32 version and entry count, fixed-size entries and
// a BLAKE3 digest of everything before it. Writers replace the whole file through a rename, so a
// reader sees either the old or the new store; any malformed store authorizes nothing.
TRUST_MAGIC :: "ECOTRUST"
TRUST_VERSION :: u32(1)
TRUST_HEADER :: 16
TRUST_LABEL_MAX :: 64
TRUST_ENTRY :: 32+8+8+1+1+TRUST_LABEL_MAX
TRUST_ENTRIES_MAX :: 4096
TRUST_DIGEST :: 32
TRUST_REVOKED :: u8(1)

Trust_Entry :: struct {
    key: [32]byte,
    // Unix seconds; an expires_at of 0 never expires.
    added_at, expires_at: u64,
    revoked: bool,
    label_len: int,
    label: [TRUST_LABEL_MAX]byte,
}

label_byte :: proc(b: byte) -> bool {
    switch b {
    case 'a'..='z', 'A'..='Z', '0'..='9', '.', '_', '-', ':', '[', ']': return true
    }
    return false
}

// Labels come from the peer or the command line, so they are shown and stored only in a
// restricted alphabet.
clean_label :: proc(text: []byte, out: []byte, fallback: string) -> int {
    n := 0
    for b in text {
        if n == len(out) { break }
        if label_byte(b) { out[n] = b; n += 1 }
    }
    if n == 0 { n = copy(out, fallback) }
    return n
}

trust_label :: proc(entry: ^Trust_Entry) -> string {
    return string(entry.label[:entry.label_len])
}

unix_now :: proc() -> u64 {
    return u64(time.to_unix_seconds(time.now()))
}

trust_active :: proc(entry: ^Trust_Entry, now: u64) -> bool {
    return !entry.revoked && (entry.expires_at == 0 || now < entry.expires_at)
}

// A missing store is empty. The entries live in the temporary allocator.
trust_load :: proc(path: string) -> (entries: []Trust_Entry, ok: bool) {
    data, err := os.read_entire_file_from_path(path, context.temp_allocator)
    if err == .Not_Exist { return nil, true }
    if err != nil { return nil, false }
    return trust_decode(data)
}

trust_decode :: proc(data: []byte) -> (entries: []Trust_Entry, ok: bool) {
    if len(data) < TRUST_HEADER+TRUST_DIGEST || string(data[:8]) != TRUST_MAGIC ||
       get_u32(data[8:]) != TRUST_VERSION {
        return nil, false
    }
    count := int(get_u32(data[12:]))
    body := TRUST_HEADER+count*TRUST_ENTRY
    if count > TRUST_ENTRIES_MAX || len(data) != body+TRUST_DIGEST { return nil, false }
    digest := blake3.hash(data[:body])
    if crypto.compare_constant_time(digest[:], data[body:]) != 1 { return nil, false }
    entries = make([]Trust_Entry, count, context.temp_allocator)
    for &entry, i in entries {
        record := data[TRUST_HEADER+i*TRUST_ENTRY:][:TRUST_ENTRY]
        copy(entry.key[:], record[:32])
        entry.added_at, entry.expires_at = get_u64(record[32:]), get_u64(record[40:])
        flags, label_len := record[48], int(record[49])
        if flags & ~TRUST_REVOKED != 0 || label_len == 0 || label_len > TRUST_LABEL_MAX { return nil, false }
        entry.revoked, entry.label_len = flags == TRUST_REVOKED, label_len
        for b, j in record[50:50+label_len] {
            if !label_byte(b) { return nil, false }
            entry.label[j] = b
        }
    }
    return entries, true
}

trust_encode :: proc(entries: []Trust_Entry) -> []byte {
    body := TRUST_HEADER+len(entries)*TRUST_ENTRY
    data := make([]byte, body+TRUST_DIGEST, context.temp_allocator)
    copy(data, TRUST_MAGIC)
    put_u32(data[8:], TRUST_VERSION)
    put_u32(data[12:], u32(len(entries)))
    for &entry, i in entries {
        record := data[TRUST_HEADER+i*TRUST_ENTRY:][:TRUST_ENTRY]
        copy(record, entry.key[:])
        put_u64(record[32:], entry.added_at)
        put_u64(record[40:], entry.expires_at)
        record[48] = TRUST_REVOKED if entry.revoked else 0
        record[49] = u8(entry.label_len)
        copy(record[50:], trust_label(&entry))
    }
    digest := blake3.hash(data[:body])
    copy(data[body:], digest[:])
    return data
}

trust_save :: proc(path: string, entries: []Trust_Entry) -> bool {
    if len(entries) > TRUST_ENTRIES_MAX { return false }
    random: [8]byte
    random_bytes(random[:])
    temp := fmt.tprintf("%s.tmp-%s", path, string(hex.encode(random[:], context.temp_allocator)))
    if !create_seed(temp, trust_encode(entries)) { return false }
    if os.rename(temp, path) != nil {
        _ = os.remove(temp)
        return false
    }
    return true
}

// Every entry is compared, so the time taken does not depend on where the key is stored.
trust_permits :: proc(path: string, key: []byte) -> bool {
    entries, ok := trust_load(path)
    if !ok || len(key) != 32 { return false }
    now := unix_now()
    found := 0
    for &entry in entries {
        found |= crypto.compare_constant_time(entry.key[:], key) & int(trust_active(&entry, now))
    }
    return found == 1
}

trust_find_label :: proc(path, label: string, key: []byte) -> bool {
    entries, ok := trust_load(path)
    if !ok { return false }
    now := unix_now()
    for &entry in entries {
        if trust_label(&entry) == label && trust_active(&entry, now) {
            copy(key, entry.key[:])
            return true
        }
    }
    return false
}

// Replaces the entry with the same key, or with the same label when by_label is set, or adds one.
trust_put :: proc(path: string, entry: Trust_Entry, by_label: bool) -> bool {
    entry := entry
    entries, ok := trust_load(path)
    if !ok { return false }
    kept := make([dynamic]Trust_Entry, 0, len(entries)+1, context.temp_allocator)
    for &existing in entries {
        same := trust_label(&existing) == trust_label(&entry) if by_label else existing.key == entry.key
        if !same { append(&kept, existing) }
    }
    append(&kept, entry)
    return trust_save(path, kept[:])
}

trust_entry :: proc(key: []byte, label: string, expires_in: u64 = 0) -> (entry: Trust_Entry) {
    copy(entry.key[:], key)
    entry.added_at = unix_now()
    if expires_in != 0 { entry.expires_at = entry.added_at+expires_in }
    entry.label_len = clean_label(transmute([]byte)label, entry.label[:], "peer")
    return
}

eco_home :: proc() -> string {
    home := os.get_env("ECO_HOME", context.temp_allocator)
    if home == "" {
        directory, err := os.user_home_dir(context.temp_allocator)
        if err != nil { return "" }
        home = fmt.tprintf("%s/.eco", directory)
    }
    _ = os.mkdir(home, {.Read_User, .Write_User, .Execute_User})
    return home
}

// Servers that pair stored, labeled by the address they were paired at.
servers_path :: proc() -> string {
    home := eco_home()
    return "" if home == "" else fmt.tprintf("%s/servers", home)
}

// ECO_PEER pins the server key; otherwise the key that pair stored for the address is used.
client_peer :: proc(address: string) -> string {
    if peer := os.get_env("ECO_PEER", context.temp_allocator); peer != "" { return peer }
    path := servers_path()
    key: [32]byte
    if address == "" || path == "" || !trust_find_label(path, address, key[:]) { return "" }
    return string(hex.encode(key[:], context.temp_allocator))
}

trust_cli :: proc(args: []string) -> int {
    if len(args) < 2 { return error_exit(USAGE) }
    command, path := args[0], args[1]
    switch command {
    case "list":
        if len(args) != 2 { return error_exit(USAGE) }
        entries, ok := trust_load(path)
        if !ok { return error_exit("invalid trust store", path) }
        now := unix_now()
        for &entry in entries {
            state := "active"
            if entry.revoked { state = "revoked" } else if !trust_active(&entry, now) { state = "expired" }
            fmt.printfln("%s\t%s\t%d\t%d\t%s", string(hex.encode(entry.key[:], context.temp_allocator)),
                         trust_label(&entry), entry.added_at, entry.expires_at, state)
        }
        return 0
    case "add":
        if len(args) < 3 || len(args) > 5 { return error_exit(USAGE) }
        key: [32]byte
        if !decode_key(args[2], key[:]) { return error_exit("expected a 64-character public key") }
        ttl: u64
        if len(args) == 5 {
            value, valid := strconv.parse_u64(args[4], 10)
            if !valid || value == 0 { return error_exit("invalid lifetime in seconds") }
            ttl = value
        }
        label := args[3] if len(args) >= 4 else "client"
        if !trust_put(path, trust_entry(key[:], label, ttl), false) { return error_exit("cannot update", path) }
        return 0
    case "revoke":
        if len(args) != 3 { return error_exit(USAGE) }
        key: [32]byte
        if !decode_key(args[2], key[:]) { return error_exit("expected a 64-character public key") }
        entries, ok := trust_load(path)
        if !ok { return error_exit("invalid trust store", path) }
        found := false
        for &entry in entries {
            if entry.key == key { entry.revoked, found = true, true }
        }
        if !found { return error_exit("key not in", path) }
        if !trust_save(path, entries) { return error_exit("cannot update", path) }
        return 0
    }
    return error_exit(USAGE)
}
