package eco

import "core:time"

VIDEO_CHUNK_HEADER :: 12 // stream ID, frame ID, chunk index, chunk count
VIDEO_CHUNK_BYTES :: KCP_MTU-VIDEO_CHUNK_HEADER
VIDEO_CHUNK_MAX :: (DESKTOP_FRAME_MAX+VIDEO_CHUNK_BYTES-1)/VIDEO_CHUNK_BYTES
VIDEO_FRAME_LIFETIME :: time.Second
VIDEO_BURST :: 4
VIDEO_BURST_INTERVAL :: 10*time.Millisecond

// One incomplete frame and one complete frame being delivered to the local consumer.
Video_Receiver :: struct {
    buffers: [2][DESKTOP_FRAME_MAX]byte,
    assembling: int,
    frame_id: u32,
    seen: [VIDEO_CHUNK_MAX]bool,
    count, received, size: int,
    started: time.Tick,
    output_size, output_offset: int,
}

video_header :: proc(out: []byte, stream_id, frame_id: u32, index, count: int) {
    put_u32(out, stream_id)
    put_u32(out[4:], frame_id)
    put_u16(out[8:], u16(index))
    put_u16(out[10:], u16(count))
}

pump_video_frame :: proc(stream: ^Stream, desktop: ^Desktop_Call) {
    if time.tick_since(desktop.deadline) >= 0 {
        desktop.phase = .Waiting
        return
    }
    if desktop.next_send != {} && time.tick_since(desktop.next_send) < 0 { return }
    desktop.next_send = time.tick_add(time.tick_now(), VIDEO_BURST_INTERVAL)

    image := desktop.response[1:desktop.response_len]
    count := (len(image)+VIDEO_CHUNK_BYTES-1)/VIDEO_CHUNK_BYTES
    packet: [KCP_MTU]byte
    for _ in 0..<VIDEO_BURST {
        start := desktop.offset
        end := min(start+VIDEO_CHUNK_BYTES, len(image))
        video_header(packet[:], stream.id, desktop.frame_id, start/VIDEO_CHUNK_BYTES, count)
        n := copy(packet[VIDEO_CHUNK_HEADER:], image[start:end])
        desktop.offset = end
        if !send_record(stream.link, .Desktop_Frame, packet[:VIDEO_CHUNK_HEADER+n], stream.link.remote) ||
           end == len(image) {
            desktop.phase = .Waiting
            break
        }
    }
}

receive_video_chunk :: proc(video: ^Video_Receiver, packet: []byte) {
    if len(packet) <= VIDEO_CHUNK_HEADER || len(packet) > KCP_MTU { return }
    frame_id := get_u32(packet[4:])
    index := int(get_u16(packet[8:]))
    count := int(get_u16(packet[10:]))
    body := packet[VIDEO_CHUNK_HEADER:]
    start := index*VIDEO_CHUNK_BYTES
    end := start+len(body)
    if frame_id == 0 || frame_id < video.frame_id || count <= 0 || count > VIDEO_CHUNK_MAX ||
       index >= count || end > DESKTOP_FRAME_MAX ||
       (index+1 < count && len(body) != VIDEO_CHUNK_BYTES) { return }

    if frame_id > video.frame_id {
        video.frame_id = frame_id
        video.count, video.received, video.size = count, 0, 0
        video.seen = {}
        video.started = time.tick_now()
    }
    if video.count != count || video.seen[index] || time.tick_since(video.started) >= VIDEO_FRAME_LIFETIME { return }

    copy(video.buffers[video.assembling][start:end], body)
    video.seen[index] = true
    video.received += 1
    if index+1 == count { video.size = end }
    if video.received == count && video.output_offset == 0 {
        video.output_size = video.size
        video.assembling = 1-video.assembling
    }
}

receive_desktop_frame :: proc(bridge: ^Bridge, link: ^Link, packet: []byte) {
    if len(packet) <= VIDEO_CHUNK_HEADER { return }
    stream := get_u32(packet)
    for call in bridge.calls {
        if call != nil && call.video != nil && call.stream != nil && call.stream.id == stream &&
           call.stream.link == link && !call.complete && !call.disconnecting {
            receive_video_chunk(call.video, packet)
            return
        }
    }
}

read_video_output :: proc(video: ^Video_Receiver, packet: []byte) -> []byte {
    if video.output_size == 0 { return nil }
    start := video.output_offset
    end := min(start+len(packet)-1, video.output_size)
    packet[0] = byte(Op.Stdout)
    copy(packet[1:], video.buffers[1-video.assembling][start:end])
    video.output_offset = end
    if end == video.output_size { video.output_size, video.output_offset = 0, 0 }
    return packet[:1+end-start]
}
