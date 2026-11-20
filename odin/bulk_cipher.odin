package eco

import "core:c"
import "core:crypto"
import "core:crypto/aes"
import "core:crypto/hkdf"
import "core:os"

when ODIN_OS == .Windows {
    foreign import platform "../.eco-deps/eco_platform.lib"
} else {
    foreign import platform "../.eco-deps/libeco_platform.a"
}
@(default_calling_convention="c")
foreign platform {
    eco_aes_context :: proc(key: ^byte, encrypt: c.int) -> rawptr ---
    eco_aes_free :: proc(ctx: rawptr) ---
    eco_aes_record :: proc(ctx, nonce, aad: rawptr, aad_len: c.int, text: rawptr,
                            count: c.int, tag: rawptr, encrypt: c.int) -> c.int ---
}

BULK_RECORD_LIMIT :: 1 << 22

Bulk_Key :: struct {
    accelerator: rawptr,
    portable: aes.Context_GCM,
    counter: u64,
}

Bulk_Cipher :: struct {
    send, receive: Bulk_Key,
}

bulk_cipher_init :: proc(cipher: ^Bulk_Cipher, transcript, seed: []byte, initiator: bool) {
    material: [64]byte
    defer crypto.zero_explicit(&material, len(material))
    label: string = "ECO2 bulk AES-256-GCM client-to-server then server-to-client"
    hkdf.extract_and_expand(.SHA256, transcript, seed, transmute([]byte)label, material[:])
    sender, receiver := material[:32], material[32:]
    if !initiator { sender, receiver = receiver, sender }
    env: [64]byte
    if os.get_env(env[:], "ECO_BULK_CRYPTO") != "portable" {
        cipher.send.accelerator = eco_aes_context(&sender[0], 1)
        cipher.receive.accelerator = eco_aes_context(&receiver[0], 0)
    }
    if cipher.send.accelerator == nil { aes.init_gcm(&cipher.send.portable, sender) }
    if cipher.receive.accelerator == nil { aes.init_gcm(&cipher.receive.portable, receiver) }
}

bulk_cipher_free :: proc(cipher: ^Bulk_Cipher) {
    eco_aes_free(cipher.send.accelerator)
    eco_aes_free(cipher.receive.accelerator)
    crypto.zero_explicit(cipher, size_of(Bulk_Cipher))
}

bulk_crypt :: proc(key: ^Bulk_Key, aad, text, tag: []byte, encrypt: bool) -> bool {
    if key.counter >= BULK_RECORD_LIMIT { return false }
    nonce: [12]byte
    put_u64(nonce[4:], key.counter)
    key.counter += 1
    if key.accelerator != nil {
        return eco_aes_record(key.accelerator, &nonce[0], raw_data(aad), c.int(len(aad)),
                              raw_data(text), c.int(len(text)), raw_data(tag), c.int(encrypt)) == 1
    }
    if encrypt {
        aes.seal_gcm(&key.portable, text, tag, nonce[:], aad, text)
        return true
    }
    return aes.open_gcm(&key.portable, text, nonce[:], aad, text, tag)
}
