package eco

import "core:c"

encode_size :: proc(dst: []byte, rows, cols: u16) {
    dst[0], dst[1] = u8(rows), u8(rows >> 8)
    dst[2], dst[3] = u8(cols), u8(cols >> 8)
}

queue_terminal :: proc(packet: []byte, op: Op, data: []byte = nil) -> int {
    size := 1+len(data)
    packet[0], packet[1], packet[2] = u8(size), u8(size >> 8), u8(op)
    copy(packet[3:], data)
    return 2+size
}

run_interactive :: proc(fd: c.int, tty: bool, rows, cols: u16) -> int {
    rows, cols := rows, cols
    if eco_fd_setup(fd, 1) < 0 { return error_exit("cannot configure local session") }
    if tty && eco_terminal_raw(0) != 0 { return error_exit("cannot configure local terminal") }
    defer if tty { eco_terminal_restore() }

    local := Local_Call{fd = fd}
    packet: [MESSAGE_MAX+2]byte
    offset, pending: int
    input_open := true
    for eco_stopping() == 0 {
        if tty && offset == pending {
            new_rows, new_cols: u16
            if eco_terminal_size(0, &new_rows, &new_cols) == 0 && (new_rows != rows || new_cols != cols) {
                size: [4]byte
                encode_size(size[:], new_rows, new_cols)
                offset, pending = 0, queue_terminal(packet[:], .Resize, size[:])
                rows, cols = new_rows, new_cols
            }
        }
        fds := [2]c.int{fd, 0}
        events := [2]c.int{POLL_READ, POLL_READ}
        if offset < pending { events[0] |= POLL_WRITE }
        count: c.int = 2 if input_open && offset == pending else 1
        if eco_poll(raw_data(fds[:]), raw_data(events[:]), count, 50) <= 0 { continue }

        if events[0] & (POLL_READ | POLL_CLOSED) != 0 {
            for _ in 0..<2 {
                response, ok := read_call_input(&local)
                if !ok { return error_exit("connection lost; remote outcome may be unknown") }
                if response == nil { continue }
                body := response[1:]
                #partial switch Op(response[0]) {
                case .Stdout, .Stderr:
                    if !write_fd(1 if Op(response[0]) == .Stdout else 2, body) {
                        return error_exit("cannot write process output")
                    }
                case .Done:
                    if len(body) != 4 { return error_exit("invalid process status") }
                    return process_exit(get_u32(body))
                case .Failure:
                    return error_exit(string(body))
                case:
                    return error_exit("unexpected process response")
                }
                break
            }
        }
        if offset < pending && events[0] & POLL_WRITE != 0 {
            data := packet[offset:pending]
            n := eco_write(fd, raw_data(data), c.int(len(data)))
            if n > 0 { offset += int(n) }
            else if n != -2 { return error_exit("cannot send process input") }
        }
        if count == 2 && events[1] & (POLL_READ | POLL_CLOSED) != 0 {
            size := eco_read(0, &packet[3], MESSAGE_MAX-1)
            if size > 0 {
                offset, pending = 0, queue_terminal(packet[:], .Input, packet[3:3+size])
            } else if size == 0 {
                input_open = false
                if tty { return 130 }
                offset, pending = 0, queue_terminal(packet[:], .Input_End)
            } else if size != -2 {
                return error_exit("cannot read local input")
            }
        }
    }
    return 130
}
