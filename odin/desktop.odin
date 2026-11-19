package eco

import "core:c"
import "core:strconv"
import "core:time"
import "core:unicode/utf8"

DESKTOP_FRAME_MAX :: 256*1024
DESKTOP_FPS_MAX :: 10
DESKTOP_TIMEOUT :: 8*time.Second

Desktop_Action :: enum u8 { Capture = 1, Click, Move, Type, Key, Scroll }
Desktop_Phase :: enum { Waiting, Write_Request, Read_Header, Read_Response, Send_Frame }
Desktop_Call :: struct {
    phase: Desktop_Phase,
    // Length-prefixed request and response, independent of the remote stream framing.
    request: [4+MESSAGE_MAX-1]byte,
    response_header: [4]byte,
    response: []byte,
    request_len, response_len, offset: int,
    deadline, next_capture, next_send: time.Tick,
    interval: time.Duration,
    frame_id: u32,
    // A video call owns the server's single streaming slot until disposal.
    video_slot: ^^Stream,
}

get_u16 :: proc(data: []byte) -> u16 {
    return u16(data[0]) | u16(data[1]) << 8
}

put_u16 :: proc(data: []byte, value: u16) {
    data[0], data[1] = byte(value), byte(value >> 8)
}

valid_desktop_input :: proc(data: []byte) -> bool {
    if len(data) == 0 { return false }
    #partial switch Desktop_Action(data[0]) {
    case .Click:  return len(data) == 6 && data[5] <= 1
    case .Move:   return len(data) == 5
    case .Type:   return len(data) > 1 && utf8.valid_string(string(data[1:]))
    case .Key:    return len(data) == 3 && get_u16(data[1:]) <= 127
    case .Scroll: return len(data) == 5
    }
    return false
}

desktop_request :: proc(args: []string, out: []byte) -> (Op, []byte, bool) {
    if len(args) == 0 { return {}, nil, false }
    switch args[0] {
    case "capture":
        return .Desktop_Capture, nil, len(args) == 1
    case "stream":
        fps := 4
        if len(args) == 2 {
            ok: bool
            fps, ok = strconv.parse_int(args[1], 10)
            if !ok || fps < 1 || fps > DESKTOP_FPS_MAX { return {}, nil, false }
        } else if len(args) != 1 { return {}, nil, false }
        out[0] = byte(fps)
        return .Desktop_Stream, out[:1], true
    case "click", "move", "scroll":
        click := args[0] == "click"
        scroll := args[0] == "scroll"
        if len(args) != 3 && !(click && len(args) == 4) { return {}, nil, false }
        action: Desktop_Action = .Scroll if scroll else (.Click if click else .Move)
        out[0] = byte(action)
        for arg, i in args[1:3] {
            value, ok := strconv.parse_int(arg, 10)
            low := int(min(i16)) if scroll else 0
            high := int(max(i16)) if scroll else int(max(u16))
            if !ok || value < low || value > high { return {}, nil, false }
            put_u16(out[1+2*i:], u16(value))
        }
        if click {
            if len(args) == 4 && args[3] != "left" && args[3] != "right" { return {}, nil, false }
            out[5] = 1 if len(args) == 4 && args[3] == "right" else 0
            return .Desktop_Input, out[:6], true
        }
        return .Desktop_Input, out[:5], true
    case "key":
        if len(args) != 2 { return {}, nil, false }
        code, ok := strconv.parse_int(args[1], 10)
        if !ok || code < 0 || code > 127 { return {}, nil, false }
        out[0] = byte(Desktop_Action.Key)
        put_u16(out[1:], u16(code))
        return .Desktop_Input, out[:3], true
    case "type":
        if len(args) != 2 || len(args[1]) == 0 || len(args[1]) >= len(out) ||
           !utf8.valid_string(args[1]) { return {}, nil, false }
        out[0] = byte(Desktop_Action.Type)
        copied := copy(out[1:], args[1])
        return .Desktop_Input, out[:1+copied], true
    }
    return {}, nil, false
}

open_desktop :: proc(server: ^Server, stream: ^Stream, call: ^Server_Call, body: []byte) {
    if server.access != .Run || stream.link.rights & CAP_RUN == 0 || stream.link.confined {
        fail_call(stream, call, "desktop requires unconfined execution")
        return
    }
    if server.desktop_socket == nil {
        fail_call(stream, call, "desktop helper not configured")
        return
    }
    video := call.op == .Desktop_Stream
    input := call.op == .Desktop_Input
    #partial switch call.op {
    case .Desktop_Stream:
        if len(body) != 1 || body[0] == 0 || body[0] > DESKTOP_FPS_MAX {
            fail_call(stream, call, "invalid desktop frame rate")
            return
        }
        if server.desktop_stream != nil {
            fail_call(stream, call, "desktop is already streaming")
            return
        }
    case .Desktop_Input:
        if !valid_desktop_input(body) { fail_call(stream, call, "invalid desktop input"); return }
    case:
        if len(body) != 0 { fail_call(stream, call, "invalid desktop capture request"); return }
    }
    call.file = eco_try_connect_local(server.desktop_socket)
    if call.file < 0 { fail_call(stream, call, "cannot connect to desktop helper"); return }

    desktop := new(Desktop_Call)
    call.desktop = desktop
    request := body if input else []byte{byte(Desktop_Action.Capture)}
    put_u32(desktop.request[:], u32(len(request)))
    desktop.request_len = 4 + copy(desktop.request[4:], request)
    if video {
        server.desktop_stream = stream
        desktop.video_slot = &server.desktop_stream
        desktop.interval = time.Second / time.Duration(body[0])
    }
    if call.op == .Desktop_Capture { stream.bulk = true }
    begin_desktop_request(desktop)
}

dispose_desktop :: proc(desktop: ^Desktop_Call) {
    if desktop.video_slot != nil { desktop.video_slot^ = nil }
    delete(desktop.response)
    free(desktop)
}

begin_desktop_request :: proc(desktop: ^Desktop_Call) {
    now := time.tick_now()
    desktop.phase = .Write_Request
    desktop.offset = 0
    desktop.deadline = time.tick_add(now, DESKTOP_TIMEOUT)
    desktop.next_capture = time.tick_add(now, desktop.interval)
}

desktop_poll_mask :: proc(desktop: ^Desktop_Call) -> c.int {
    #partial switch desktop.phase {
    case .Write_Request: return POLL_WRITE
    case .Read_Header, .Read_Response: return POLL_READ
    }
    return 0
}

pump_desktop :: proc(stream: ^Stream, call: ^Server_Call) -> bool {
    desktop := call.desktop
    if desktop.phase == .Waiting {
        if time.tick_since(desktop.next_capture) < 0 { return false }
        begin_desktop_request(desktop)
    }
    if desktop.phase == .Send_Frame {
        if call.op == .Desktop_Stream { return false }
        image := desktop.response[1:desktop.response_len]
        end := min(desktop.offset+MESSAGE_MAX-1, len(image))
        reply(stream, .Stdout, image[desktop.offset:end])
        desktop.offset = end
        if end == len(image) { finish_call(stream, call, 0) }
        return true
    }
    if time.tick_since(desktop.deadline) >= 0 {
        fail_call(stream, call, "desktop helper timed out")
        return false
    }
    data: []byte
    #partial switch desktop.phase {
    case .Write_Request: data = desktop.request[:desktop.request_len]
    case .Read_Header: data = desktop.response_header[:]
    case .Read_Response: data = desktop.response[:desktop.response_len]
    }
    left := data[desktop.offset:]
    count := eco_write(call.file, raw_data(left), c.int(len(left))) if desktop.phase == .Write_Request else
             eco_read(call.file, raw_data(left), c.int(len(left)))
    if count == -2 { return false }
    if count <= 0 { fail_call(stream, call, "desktop helper disconnected"); return false }
    desktop.offset += int(count)
    if desktop.offset < len(data) { return true }
    desktop.offset = 0

    #partial switch desktop.phase {
    case .Write_Request:
        desktop.phase = .Read_Header
    case .Read_Header:
        size := get_u32(desktop.response_header[:])
        if size == 0 || size > DESKTOP_FRAME_MAX+1 {
            fail_call(stream, call, "invalid desktop response length")
            return false
        }
        desktop.response_len = int(size)
        if int(size) > len(desktop.response) {
            delete(desktop.response)
            // Video reuses this buffer even when later JPEGs vary in size.
            capacity := DESKTOP_FRAME_MAX+1 if call.op == .Desktop_Stream else int(size)
            desktop.response = make([]byte, capacity)
        }
        desktop.phase = .Read_Response
    case .Read_Response:
        response := desktop.response[:desktop.response_len]
        if response[0] != 0 {
            if len(response) <= 1 || len(response) > MESSAGE_MAX {
                fail_call(stream, call, "desktop helper failed")
            } else {
                fail_call(stream, call, string(response[1:]))
            }
            return false
        }
        if call.op == .Desktop_Input && len(response) == 1 {
            finish_call(stream, call, 0)
            return false
        }
        if call.op == .Desktop_Input || len(response) < 5 ||
           response[1] != 0xff || response[2] != 0xd8 ||
           response[len(response)-2] != 0xff || response[len(response)-1] != 0xd9 {
            fail_call(stream, call, "invalid JPEG from desktop helper")
            return false
        }
        desktop.phase = .Send_Frame
        desktop.frame_id += 1
        desktop.next_send = {}
        desktop.deadline = time.tick_add(time.tick_now(), VIDEO_FRAME_LIFETIME)
    }
    return true
}
