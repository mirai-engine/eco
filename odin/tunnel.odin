package eco

import "core:c"
import "core:fmt"
import "core:net"
import "core:time"

when ODIN_OS == .Windows {
    foreign import platform "../.eco-deps/eco_platform.lib"
} else {
    foreign import platform "../.eco-deps/libeco_platform.a"
}

@(default_calling_convention="c")
foreign platform {
    eco_net_open :: proc(address: cstring, datagram: c.int, connecting: ^c.int) -> c.int ---
    eco_net_ready :: proc(fd: c.int) -> c.int ---
    eco_net_fin :: proc(fd: c.int) -> c.int ---
    eco_net_recv_datagram :: proc(fd: c.int, data: rawptr, n: c.int) -> c.int ---
}

open_tunnel :: proc(stream: ^Stream, call: ^Server_Call, address: []byte) {
    ep, valid := net.parse_endpoint(string(address))
    if !valid || ep.port <= 0 || ep.port > 65535 {
        fail_call(stream, call, "expected numeric tunnel target")
        return
    }
    name: [96]byte
    if len(address) >= len(name) {
        fail_call(stream, call, "invalid tunnel target")
        return
    }
    copy(name[:], address)
    opening: c.int
    call.file = eco_net_open(cstring(&name[0]), c.int(call.op == .Udp), &opening)
    if call.file < 0 {
        fail_call(stream, call, "cannot connect tunnel target")
        return
    }
    call.connecting = opening != 0
    call.deadline = time.tick_add(time.tick_now(), 10*time.Second)
    if !call.connecting { reply(stream, .Ready) }
}

pump_tunnel :: proc(stream: ^Stream, call: ^Server_Call, buffer: []byte) -> bool {
    if call.connecting {
        connected := eco_net_ready(call.file)
        if connected < 0 || time.tick_since(call.deadline) > 0 {
            fail_call(stream, call, "cannot connect tunnel target")
            return false
        }
        if connected == 0 { return false }
        call.connecting = false
        reply(stream, .Ready)
    }
    if call.output_end {
        if call.input_end { finish_call(stream, call, 0) }
        return false
    }
    datagram := call.op == .Udp
    n := eco_net_recv_datagram(call.file, raw_data(buffer), c.int(len(buffer))) if datagram else
        eco_read(call.file, raw_data(buffer), c.int(len(buffer)))
    if n == -2 { return false }
    if n == -3 && datagram { return true } // a datagram is dropped rather than truncated
    if n < 0 {
        fail_call(stream, call, "tunnel target disconnected")
        return false
    }
    if n == 0 && !datagram {
        call.output_end = true
        reply(stream, .Output_End)
        if call.input_end { finish_call(stream, call, 0) }
        return false
    }
    reply(stream, .Stdout, buffer[:n])
    return true
}

Relay :: struct {
    service: c.int,
    ipc: Local_Call,
    inbound, outbound: [MESSAGE_MAX+2]byte,
    to_service, service_offset, to_ipc, ipc_offset: int,
    sent_eof, peer_eof, ready: bool,
    sender: net.Endpoint,
    touched: time.Tick,
}

close_relay :: proc(relay: ^^Relay) {
    close_fd(&relay^.ipc.fd)
    close_fd(&relay^.service)
    free(relay^)
    relay^ = nil
}

new_relay :: proc(service: c.int, target: string, sender: net.Endpoint = {}) -> ^Relay {
    ipc := dial_local()
    if ipc < 0 { return nil }
    op := Op.Tcp if service >= 0 else Op.Udp
    if !send_local(ipc, op, transmute([]byte)target) || eco_fd_setup(ipc, 1) < 0 {
        _ = eco_close(ipc)
        return nil
    }
    relay := new(Relay)
    relay.service = service
    relay.ipc.fd = ipc
    relay.sender = sender
    relay.touched = time.tick_now()
    return relay
}

queue_relay :: proc(relay: ^Relay, op: Op, data: []byte) {
    packet: [MESSAGE_MAX]byte
    packet[0] = byte(op)
    copy(packet[1:], data)
    relay.to_ipc = frame_local(relay.inbound[:], packet[:len(data)+1])
    relay.ipc_offset = 0
}

tick_relay :: proc(relay: ^Relay, udp: net.UDP_Socket) -> bool {
    datagram := relay.service < 0
    if datagram && time.tick_since(relay.touched) >= 30*time.Second { return false }
    if relay.to_ipc > relay.ipc_offset && relay.ready {
        data := relay.inbound[relay.ipc_offset:relay.to_ipc]
        n := eco_write(relay.ipc.fd, raw_data(data), c.int(len(data)))
        if n > 0 { relay.ipc_offset += int(n) }
        else if n != -2 { return false }
    }

    if relay.to_service > relay.service_offset {
        data := relay.outbound[relay.service_offset:relay.to_service]
        n := eco_write(relay.service, raw_data(data), c.int(len(data)))
        if n > 0 { relay.service_offset += int(n) }
        else if n != -2 { return false }
    }
    if relay.to_service == relay.service_offset {
        for _ in 0..<2 {
            response, ok := read_call_input(&relay.ipc)
            if !ok { return false }
            if response == nil { continue }
            #partial switch Op(response[0]) {
            case .Ready:
                relay.ready = true
            case .Stdout:
                relay.touched = time.tick_now()
                if datagram {
                    _, _ = net.send_udp(udp, response[1:], relay.sender)
                } else {
                    relay.to_service = copy(relay.outbound[:], response[1:])
                    relay.service_offset = 0
                }
            case .Output_End:
                if !datagram && !relay.peer_eof {
                    _ = eco_net_fin(relay.service)
                    relay.peer_eof = true
                }
            case .Done:
                return false
            case .Failure:
                fmt.eprintln("eco: tunnel:", string(response[1:]))
                return false
            case:
                return false
            }
            break
        }
    }
    if !datagram && relay.ready && !relay.sent_eof && relay.to_ipc == relay.ipc_offset {
        buffer: [MESSAGE_MAX-1]byte
        n := eco_read(relay.service, raw_data(buffer[:]), c.int(len(buffer)))
        if n > 0 {
            queue_relay(relay, .Input, buffer[:n])
        } else if n == 0 {
            queue_relay(relay, .Input_End, nil)
            relay.sent_eof = true
        } else if n != -2 {
            return false
        }
    }
    return true
}

forward :: proc(bind: net.Endpoint, target_text: string, datagram: bool) -> int {
    udp: net.UDP_Socket
    tcp: net.TCP_Socket
    service: c.int
    if datagram {
        socket, err := net.make_bound_udp_socket(bind.address, bind.port)
        if err != nil { return error_exit("cannot listen for UDP forward", err) }
        udp, service = socket, eco_socket_fd(uintptr(socket))
        if service < 0 { net.close(socket); return error_exit("cannot register UDP socket") }
    } else {
        socket, err := net.listen_tcp(bind, STREAM_MAX)
        if err != nil { return error_exit("cannot listen for TCP forward", err) }
        tcp, service = socket, eco_socket_fd(uintptr(socket))
        if service < 0 { net.close(socket); return error_exit("cannot register TCP socket") }
    }
    defer _ = eco_close(service)
    if eco_fd_setup(service, 1) < 0 { return error_exit("cannot configure local forward") }
    _ = eco_ring_setup()
    defer eco_ring_close()
    fmt.eprintfln("eco forwarding port %d -> %s", bind.port, target_text)
    relays: [STREAM_MAX]^Relay
    defer for &relay in relays { if relay != nil { close_relay(&relay) } }
    for eco_stopping() == 0 {
        if datagram {
            for _ in 0..<32 {
                packet: [MESSAGE_MAX]byte
                n, from, err := net.recv_udp(udp, packet[:])
                if err != nil { break }
                if n >= len(packet) { continue }
                match, slot: ^^Relay
                for &relay in relays {
                    if relay == nil { slot = &relay }
                    else if same_endpoint(relay.sender, from) { match = &relay; break }
                }
                if match == nil && slot != nil {
                    slot^ = new_relay(-1, target_text, from)
                    if slot^ != nil { match = slot }
                }
                if match != nil && match^.ipc_offset == match^.to_ipc {
                    queue_relay(match^, .Input, packet[:n])
                    match^.touched = time.tick_now()
                }
            }
        } else {
            for &relay in relays {
                if relay != nil { continue }
                socket, _, err := net.accept_tcp(tcp)
                if err != nil { break }
                fd := eco_socket_fd(uintptr(socket))
                if fd < 0 { net.close(socket); continue }
                if eco_fd_setup(fd, 1) < 0 { _ = eco_close(fd); continue }
                relay = new_relay(fd, target_text)
                if relay == nil { _ = eco_close(fd); continue }
            }
        }
        fds, events: [66]c.int
        fds[0], events[0] = service, POLL_READ
        count := 1
        for &relay in relays {
            if relay == nil { continue }
            if !tick_relay(relay, udp) {
                close_relay(&relay)
                continue
            }
            fds[count] = relay.ipc.fd
            if relay.to_service == relay.service_offset { events[count] |= POLL_READ }
            if relay.to_ipc > relay.ipc_offset && relay.ready { events[count] |= POLL_WRITE }
            count += 1
            if relay.service >= 0 {
                fds[count] = relay.service
                if !relay.sent_eof && relay.ready && relay.to_ipc == relay.ipc_offset { events[count] |= POLL_READ }
                if relay.to_service > relay.service_offset { events[count] |= POLL_WRITE }
                count += 1
            }
        }
        _ = eco_poll(raw_data(fds[:]), raw_data(events[:]), c.int(count), 500)
    }
    return 0
}
