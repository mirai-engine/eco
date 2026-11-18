package eco

import "base:runtime"
import "core:c"
import "core:crypto"

foreign import platform "../.eco-deps/eco_platform.lib"

foreign platform {
    eco_dup_file :: proc "c" (fd: c.int) -> c.int ---
    eco_bulk_thread :: proc "c" (work: proc "c" (rawptr), data: rawptr, fd: c.int) -> c.int ---
}

Windows_Bulk_Transfer :: struct {
    fd, scope: c.int,
    rights: u8,
    access: Access,
    expiry: u64,
    transcript, seed: [32]byte,
}

windows_bulk_worker :: proc "c" (data: rawptr) {
    context = runtime.default_context()
    transfer := cast(^Windows_Bulk_Transfer)data
    defer {
        crypto.zero_explicit(&transfer.seed, len(transfer.seed))
        close_fd(&transfer.scope)
        free(transfer)
    }
    cipher: Bulk_Cipher
    bulk_cipher_init(&cipher, transfer.transcript[:], transfer.seed[:], false)
    defer bulk_cipher_free(&cipher)
    _ = bulk_server_transfer(transfer.fd, transfer.scope, transfer.rights, transfer.access, &cipher, transfer.expiry)
}

start_windows_bulk :: proc(pending: ^Bulk_Pending, access: Access) -> c.int {
    if eco_bulk_socket(pending.fd) < 0 { return -1 }
    scope := eco_dup_file(pending.scope)
    if scope < 0 { return -1 }
    transfer := new(Windows_Bulk_Transfer)
    transfer^ = {pending.fd, scope, pending.rights, access, pending.expiry, pending.transcript, pending.seed}
    worker := eco_bulk_thread(windows_bulk_worker, transfer, pending.fd)
    if worker < 0 {
        crypto.zero_explicit(&transfer.seed, len(transfer.seed))
        free(transfer)
        _ = eco_close(scope)
        return -1
    }
    return worker
}
