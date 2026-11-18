package eco

import "core:c"
import "core:crypto"
import "core:crypto/ecdh"
import "core:crypto/ed25519"
import "core:encoding/hex"
import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"

CAP_DOMAIN :: "ECO2 capability v1"
CAP_PREFIX :: 76
CAP_MAX_PATH :: 160
CAP_MAX :: CAP_PREFIX+CAP_MAX_PATH+ed25519.SIGNATURE_SIZE
CAP_READ :: u8(1)
CAP_WRITE :: u8(2)
CAP_RUN :: u8(4)
CAP_TUNNEL :: u8(8)
CAP_ALL :: CAP_READ | CAP_WRITE | CAP_RUN | CAP_TUNNEL
CAP_MAX_TTL :: 7*24*60*60

Policy :: struct {
    issuer: ed25519.Public_Key,
    required: bool,
    server_key: [32]byte,
}

Grant :: struct {
    scope: string,
    expiry: u64,
    mask: u8,
}

decode_key :: proc(text: string, buffer: []byte) -> bool {
    bytes, ok := hex.decode_into_buffer(transmute([]byte)text, buffer)
    return ok && len(bytes) == len(buffer)
}

read_private_seed :: proc(path: string, bytes: []byte) -> bool {
    name := strings.clone_to_cstring(path, context.temp_allocator)
    fd := eco_safe_private_file(name)
    if fd < 0 { return false }
    defer _ = eco_close(fd)
    return read_fully(fd, bytes)
}

create_seed :: proc(path: string, bytes: []byte) -> bool {
    file, err := os.open(path, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
    if err != nil { return false }
    n, write_err := os.write(file, bytes)
    close_err := os.close(file)
    if n != len(bytes) || write_err != nil || close_err != nil {
        _ = os.remove(path)
        return false
    }
    return true
}

issuer_keygen :: proc(path: string) -> int {
    key: ed25519.Private_Key
    defer ed25519.private_key_clear(&key)
    if !ed25519.private_key_generate(&key) { return error_exit("cannot generate issuer key") }
    bytes: [32]byte
    defer crypto.zero_explicit(&bytes, len(bytes))
    ed25519.private_key_bytes(&key, bytes[:])
    if !create_seed(path, bytes[:]) { return error_exit("cannot create issuer key") }
    ed25519.private_key_public_bytes(&key, bytes[:])
    fmt.println(string(hex.encode(bytes[:], context.temp_allocator)))
    return 0
}

valid_scope :: proc(path: string) -> bool {
    if len(path) == 0 || len(path) > CAP_MAX_PATH || strings.index_byte(path, 0) >= 0 { return false }
    if path == "." { return true }
    unparsed := path
    for {
        slash := strings.index_byte(unparsed, '/')
        component := unparsed if slash < 0 else unparsed[:slash]
        if component == "" || component == "." || component == ".." { return false }
        if slash < 0 { return true }
        unparsed = unparsed[slash+1:]
    }
}

issue_capability :: proc(args: []string) -> int {
    if len(args) != 6 { return error_exit(USAGE) }
    seed: [32]byte
    key: ed25519.Private_Key
    defer crypto.zero_explicit(&seed, len(seed))
    defer ed25519.private_key_clear(&key)
    if !read_private_seed(args[0], seed[:]) || !ed25519.private_key_set_bytes(&key, seed[:]) {
        return error_exit("invalid issuer key")
    }
    ttl, ok := strconv.parse_int(args[4], 10)
    if !ok || ttl <= 0 || ttl > CAP_MAX_TTL || !valid_scope(args[5]) {
        return error_exit("invalid duration or grant path")
    }

    mask: u8
    for letter in args[3] {
        switch letter {
        case 'r': mask |= CAP_READ
        case 'w': mask |= CAP_WRITE
        case 'x': mask |= CAP_RUN
        case 't': mask |= CAP_TUNNEL
        case: return error_exit("rights must use r, w, x, or t")
        }
    }
    if mask == 0 || (mask & (CAP_RUN | CAP_TUNNEL) != 0 && args[5] != ".") {
        return error_exit("execution and tunnel grants require full root scope")
    }

    buffer: [len(CAP_DOMAIN)+CAP_MAX]byte
    copy(buffer[:], CAP_DOMAIN)
    tok := buffer[len(CAP_DOMAIN):]
    tok[0], tok[1] = 1, mask
    expiry := u64(time.to_unix_seconds(time.now())) + u64(ttl)
    put_u64(tok[2:], expiry)
    if !decode_key(args[1], tok[10:42]) || !decode_key(args[2], tok[42:74]) {
        return error_exit("invalid server or client public key")
    }
    scope := args[5]
    tok[74] = u8(len(scope))
    copy(tok[CAP_PREFIX:], scope)
    end := CAP_PREFIX+len(scope)
    ed25519.sign(&key, buffer[:len(CAP_DOMAIN)+end], tok[end:end+ed25519.SIGNATURE_SIZE])
    fmt.println(string(hex.encode(tok[:end+ed25519.SIGNATURE_SIZE], context.temp_allocator)))
    return 0
}

verify_capability :: proc(policy: ^Policy, peer: ^ecdh.Public_Key, token: []byte) -> (Grant, bool) {
    if !policy.required {
        return Grant{scope = ".", mask = CAP_ALL}, len(token) == 0
    }
    if len(token) < CAP_PREFIX+1+ed25519.SIGNATURE_SIZE || len(token) > CAP_MAX { return {}, false }
    scope_len := int(token[74])
    end := CAP_PREFIX+scope_len
    if token[0] != 1 || token[1] == 0 || token[1] & ~CAP_ALL != 0 || token[75] != 0 ||
       len(token) != end+ed25519.SIGNATURE_SIZE || !valid_scope(string(token[CAP_PREFIX:end])) ||
       string(token[10:42]) != string(policy.server_key[:]) {
        return {}, false
    }
    client: [32]byte
    ecdh.public_key_bytes(peer, client[:])
    if string(token[42:74]) != string(client[:]) { return {}, false }
    expiry := get_u64(token[2:])
    now := u64(time.to_unix_seconds(time.now()))
    if expiry <= now || expiry-now > CAP_MAX_TTL { return {}, false }
    buffer: [len(CAP_DOMAIN)+CAP_MAX]byte
    copy(buffer[:], CAP_DOMAIN)
    copy(buffer[len(CAP_DOMAIN):], token[:end])
    if !ed25519.verify(&policy.issuer, buffer[:len(CAP_DOMAIN)+end], token[end:]) {
        return {}, false
    }
    scope := string(token[CAP_PREFIX:end])
    if token[1] & (CAP_RUN | CAP_TUNNEL) != 0 && scope != "." { return {}, false }
    return Grant{scope, expiry, token[1]}, true
}

open_scope :: proc(root: c.int, grant: Grant) -> c.int {
    leaf: [256]byte
    parent := parent_for(root, transmute([]byte)grant.scope, &leaf)
    if parent < 0 { return -1 }
    defer _ = eco_close(parent)
    return eco_open(parent, cstring(&leaf[0]), 1)
}
