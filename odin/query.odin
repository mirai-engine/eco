package eco

import "core:time"

// Queries are read-only and can be repeated after loss without allocating a reliable stream.
QUERY_PREFIX :: 4
QUERY_MAX_ATTEMPTS :: 10

send_query_result :: proc(link: ^Link, id: []byte, op: Op, data: []byte = nil) {
    response: [256]byte
    copy(response[:QUERY_PREFIX], id)
    response[QUERY_PREFIX] = byte(op)
    n := copy(response[QUERY_PREFIX+1:], data)
    _ = send_record(link, .Query_Result, response[:QUERY_PREFIX+1+n], link.remote)
}

query_error :: proc(link: ^Link, id: []byte, message: string) {
    send_query_result(link, id, .Failure, transmute([]byte)message)
}

answer_query :: proc(link: ^Link, request: []byte) {
    if len(request) <= QUERY_PREFIX || get_u32(request) == 0 { return }
    id, op := request[:QUERY_PREFIX], Op(request[QUERY_PREFIX])
    data := request[QUERY_PREFIX+1:]
    #partial switch op {
    case .Ping:
        if len(data) == 0 { send_query_result(link, id, .Done) }
    case .Stat:
        if link.rights & CAP_READ == 0 { query_error(link, id, "reads are disabled"); return }
        leaf: [256]byte
        parent := parent_for(link.scope, data, &leaf)
        if parent < 0 { query_error(link, id, "invalid or inaccessible path"); return }
        defer _ = eco_close(parent)
        size, stamp: u64
        kind: u8
        if eco_stat(parent, cstring(&leaf[0]), &size, &kind, &stamp) < 0 {
            query_error(link, id, "path does not exist or cannot be inspected")
            return
        }
        metadata: [17]byte
        metadata[0] = kind
        put_u64(metadata[1:], size)
        put_u64(metadata[9:], stamp)
        send_query_result(link, id, .Info, metadata[:])
    }
}

has_pending_query :: proc(bridge: ^Bridge, link: ^Link) -> bool {
    for call in bridge.calls {
        if call != nil && call.query_id != 0 && call.query_link == link { return true }
    }
    return false
}

retry_query :: proc(call: ^Local_Call) {
    now := time.tick_now()
    if call.next_query != {} && time.tick_diff(call.next_query, now) < 0 { return }
    if call.query_attempts >= QUERY_MAX_ATTEMPTS {
        call.query_id = 0
        local_failure(call, "remote query timed out")
        return
    }
    data: [QUERY_PREFIX+MESSAGE_MAX]byte
    put_u32(data[:], call.query_id)
    copy(data[QUERY_PREFIX:], call.input[2:2+call.query_len])
    link := call.query_link
    _ = send_record(link, .Query, data[:QUERY_PREFIX+call.query_len], link.remote)
    delay := min(10*time.Millisecond << u32(call.query_attempts), 500*time.Millisecond)
    call.next_query = time.tick_add(now, delay)
    call.query_attempts += 1
}

receive_query_result :: proc(bridge: ^Bridge, link: ^Link, result: []byte) {
    if len(result) <= QUERY_PREFIX || len(result) > 256 { return }
    id, op := get_u32(result), Op(result[QUERY_PREFIX])
    if id == 0 || (op != .Done && op != .Failure && op != .Info) { return }
    for call in bridge.calls {
        if call == nil || call.query_id != id || call.query_link != link { continue }
        call.query_id = 0
        call.out_pos, call.out_len = 0, 0
        if op != .Done {
            call.out_len = frame_local(call.output[:], result[QUERY_PREFIX:])
        }
        if op != .Failure {
            done := [5]byte{byte(Op.Done), 0, 0, 0, 0}
            call.out_len += frame_local(call.output[call.out_len:], done[:])
        }
        call.complete = true
        return
    }
}
