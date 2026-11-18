package eco

import "core:os"
import "core:strconv"
import "core:time"

PACER_BURST :: 64*1024
PACER_SLOTS :: 32
BULK_QUEUE :: 48

Queued_Packet :: struct {
    length: int,
    data: [KCP_MTU]byte,
}

Pacer :: struct {
    queued: [PACER_SLOTS]Queued_Packet,
    first, count: int,
    updated: time.Tick,
    // Byte credits scaled by 1,000,000 to keep sub-microsecond precision.
    credit: i64,
}

configured_bulk_limit: int = 10_000

load_bulk_limit :: proc() {
    env: [32]byte
    value := os.get_env(env[:], "ECO_ODIN_BULK_MBPS")
    configured_bulk_limit = 10_000
    if value != "" {
        if mbps, ok := strconv.parse_int(value, 10); ok && mbps >= 1 && mbps <= 100_000 {
            configured_bulk_limit = mbps
        }
    }
}

window_for :: proc(stream: ^Stream) -> int {
    return BULK_QUEUE if stream != nil && stream.bulk else CALL_QUEUE
}

bulk_segments :: proc(data: []byte) -> bool {
    // Internal KCP output is already framed and can combine ACKs with PUSH segments.
    rest := data
    for len(rest) >= KCP_OVERHEAD {
        if rest[4] == 81 && get_u32(rest[20:]) >= 512 { return true }
        rest = rest[KCP_OVERHEAD+int(get_u32(rest[20:])):]
    }
    return false
}

refill :: proc(pacer: ^Pacer) {
    now := time.tick_now()
    if pacer.updated == {} {
        pacer.credit = PACER_BURST*1_000_000
    } else {
        elapsed := min(i64(time.tick_diff(pacer.updated, now)), 5_000_000_000)
        pacer.credit = min(i64(PACER_BURST)*1_000_000,
            pacer.credit + elapsed*i64(configured_bulk_limit)*125)
    }
    pacer.updated = now
}

spend :: proc(link: ^Link, data: []byte) -> bool {
    pacer := link.pacer
    cost := i64(HEADER_SIZE+len(data)+16+28)*1_000_000
    if pacer.credit < cost { return false }
    pacer.credit -= cost
    _ = send_record(link, .Data, data, link.remote)
    return true
}

paced_output :: proc(link: ^Link, data: []byte) {
    if link.pacer == nil { link.pacer = new(Pacer) }
    pacer := link.pacer
    refill(pacer)
    if pacer.count == 0 && spend(link, data) { return }
    if pacer.count == PACER_SLOTS { return } // KCP retransmits data if backpressure fills the queue
    packet := &pacer.queued[(pacer.first+pacer.count)%PACER_SLOTS]
    packet.length = copy(packet.data[:], data)
    pacer.count += 1
}

drain_pacer :: proc(link: ^Link) -> bool {
    pacer := link.pacer
    if pacer == nil || pacer.count == 0 { return false }
    refill(pacer)
    for pacer.count > 0 {
        packet := &pacer.queued[pacer.first]
        if !spend(link, packet.data[:packet.length]) { break }
        pacer.first = (pacer.first+1)%PACER_SLOTS
        pacer.count -= 1
    }
    return pacer.count > 0
}

release_pacer :: proc(link: ^Link) {
    if link.pacer != nil { free(link.pacer); link.pacer = nil }
}
