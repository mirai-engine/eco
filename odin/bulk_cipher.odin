package eco

import "core:crypto"
import "core:crypto/aegis"
import "core:crypto/hkdf"

BULK_TAG :: aegis.TAG_SIZE_128

// Each direction has its own AEGIS-256 key; the record counter is the nonce, so a key never
// seals two records under one nonce.
Bulk_Key :: struct {
    aead: aegis.Context,
    counter: u64,
}

Bulk_Cipher :: struct {
    send, receive: Bulk_Key,
}

bulk_cipher_init :: proc(cipher: ^Bulk_Cipher, transcript, seed: []byte, initiator: bool) {
    material: [2*aegis.KEY_SIZE_256]byte
    defer crypto.zero_explicit(&material, len(material))
    label: string = "ECO3 bulk AEGIS-256 client-to-server then server-to-client"
    hkdf.extract_and_expand(.SHA256, transcript, seed, transmute([]byte)label, material[:])
    sender, receiver := material[:aegis.KEY_SIZE_256], material[aegis.KEY_SIZE_256:]
    if !initiator { sender, receiver = receiver, sender }
    aegis.init(&cipher.send.aead, sender)
    aegis.init(&cipher.receive.aead, receiver)
}

bulk_cipher_free :: proc(cipher: ^Bulk_Cipher) {
    aegis.reset(&cipher.send.aead)
    aegis.reset(&cipher.receive.aead)
    crypto.zero_explicit(cipher, size_of(Bulk_Cipher))
}

bulk_crypt :: proc(key: ^Bulk_Key, aad, text, tag: []byte, encrypt: bool) -> bool {
    if key.counter == max(u64) { return false }
    nonce: [aegis.IV_SIZE_256]byte
    put_u64(nonce[:], key.counter)
    key.counter += 1
    if encrypt {
        aegis.seal(&key.aead, text, tag, nonce[:], aad, text)
        return true
    }
    return aegis.open(&key.aead, text, nonce[:], aad, text, tag)
}
