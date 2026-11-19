package eco

import "core:c"
import "core:crypto"
import "core:crypto/ecdh"
import "core:crypto/ed25519"
import "core:encoding/hex"
import "core:fmt"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:time"
import "deps:blake3"

USAGE :: `usage: eco-odin COMMAND
  keygen KEY                         create a 0600 X25519 key and print its public key
  serve UDP KEY CLIENTS ROOT [read|write|run|tunnel] [ISSUER_PUBLIC_KEY]
                                     CLIENTS lists authorized client keys; approved pairings add to it
  pair UDP [NAME]                    pair with a server using ECO_ODIN_KEY; its operator approves
  issuer-keygen KEY
  grant ISSUER_KEY SERVER_KEY CLIENT_KEY RWXT TTL_SECONDS PATH
  client SOCKET UDP KEY PEER         keep a client daemon in the foreground
  ping                               request via the local daemon
  ping-early UDP KEY PEER             send a cold 0-RTT ping in Noise IK's first message
  stat|list|hash|watch PATH            native operations inside the server root
  read PATH                          write remote bytes to stdout
  get REMOTE LOCAL
  write REMOTE                       read bytes from stdin
  put LOCAL REMOTE
  run [--stdin] [--cwd DIR] [--timeout-ms N] -- PROGRAM [ARG...]
  start [--id HEX] [--cwd DIR] [--timeout-ms N] -- PROGRAM [ARG...]
  attach ID [STDOUT_OFFSET STDERR_OFFSET] | jobs | kill ID
  forward|forward-udp LISTEN TARGET
  tty [--cwd DIR] [--timeout-ms N] -- PROGRAM [ARG...]

Client environment: ECO_ODIN_SOCKET, ECO_ODIN_ADDR, ECO_ODIN_KEY, ECO_ODIN_HOME and, unless pair
stored the server for ECO_ODIN_ADDR in ECO_ODIN_HOME/known_servers, ECO_ODIN_PEER.
Paths sent to the server are relative to ROOT. Peer keys are 64 hex characters.
`

error_exit :: proc(message: string, detail: any = nil) -> int {
    if detail == nil {
        fmt.eprintln("eco-odin:", message)
    } else {
        fmt.eprintln("eco-odin:", message, detail)
    }
    return 125
}

keygen :: proc(path: string) -> int {
    key: ecdh.Private_Key
    defer ecdh.private_key_clear(&key)
    if !ecdh.private_key_generate(&key, .X25519) { return error_exit("cannot generate key") }
    bytes: [32]byte
    defer crypto.zero_explicit(&bytes, len(bytes))
    ecdh.private_key_bytes(&key, bytes[:])
    if !create_seed(path, bytes[:]) { return error_exit("cannot create key") }
    ecdh.private_key_public_bytes(&key, bytes[:])
    fmt.println(string(hex.encode(bytes[:], context.temp_allocator)))
    return 0
}

load_private :: proc(path: string, key: ^ecdh.Private_Key) -> bool {
    bytes: [32]byte
    defer crypto.zero_explicit(&bytes, len(bytes))
    return read_private_seed(path, bytes[:]) && ecdh.private_key_set_bytes(key, .X25519, bytes[:])
}

load_keys :: proc(path, peer_text: string, key: ^ecdh.Private_Key, peer: ^ecdh.Public_Key) -> bool {
    bytes: [32]byte
    return load_private(path, key) && decode_key(peer_text, bytes[:]) &&
           ecdh.public_key_set_bytes(peer, .X25519, bytes[:])
}

dispatch_platform :: proc(args: []string) -> int {
    role := args[0]
    count := 4 if role == "ping-early" else 5
    if len(args) < count || len(args) > count+2 || (role != "serve" && len(args) != count) {
        return error_exit(USAGE)
    }
    shift := 1 if role == "client" else 0
    endpoint, ok := net.parse_endpoint(args[1+shift])
    if !ok || endpoint.port <= 0 || endpoint.port > 65535 { return error_exit("expected a numeric IP:port") }
    own: ecdh.Private_Key
    defer ecdh.private_key_clear(&own)
    peer: ecdh.Public_Key
    if role == "serve" {
        if !load_private(args[2], &own) { return error_exit("invalid identity. It must be a private regular file") }
    } else if !load_keys(args[2+shift], args[3+shift], &own, &peer) {
        return error_exit("invalid identity or peer. Identity must be a private regular file")
    }
    token: []byte
    if role != "serve" {
        if encoded := os.get_env("ECO_ODIN_CAPABILITY", context.temp_allocator); encoded != "" {
            valid: bool
            if len(encoded) > CAP_MAX*2 { return error_exit("invalid capability") }
            token, valid = hex.decode(transmute([]byte)encoded, context.temp_allocator)
            if !valid { return error_exit("invalid capability") }
        }
    }
    switch role {
    case "serve":
        access := Access.Read
        if len(args) >= count+1 {
            switch args[5] {
            case "read": access = .Read
            case "write": access = .Write
            case "run": access = .Run
            case "tunnel": access = .Tunnel
            case: return error_exit("expected read, write, tunnel, or run")
            }
        }
        policy: Policy
        if len(args) == count+2 {
            issuer: [32]byte
            if !decode_key(args[6], issuer[:]) || !ed25519.public_key_set_bytes(&policy.issuer, issuer[:]) {
                return error_exit("invalid issuer public key")
            }
            policy.required = true
            ecdh.private_key_public_bytes(&own, policy.server_key[:])
        }
        jobs_buffer: [1024]byte
        jobs := os.get_env(jobs_buffer[:], "ECO_ODIN_JOBS")
        if jobs != "" {
            name := strings.clone_to_cstring(jobs, context.temp_allocator)
            if !(os.is_absolute_path(jobs)) || eco_check_private_dir(name) != 1 {
                return error_exit("ECO_ODIN_JOBS must be an absolute, private directory owned by you")
            }
        }
        return serve(endpoint, &own, args[3], args[4], access, policy, jobs)
    case "client":
        return client_daemon(args[1], endpoint, &own, &peer, token)
    case "ping-early":
        udp, err := net.make_unbound_udp_socket(family(endpoint))
        if err != nil { return error_exit("cannot open UDP", err) }
        udp_fd := eco_socket_fd(uintptr(udp))
        if udp_fd < 0 { net.close(udp); return error_exit("cannot register UDP socket") }
        defer _ = eco_close(udp_fd)
        if eco_fd_setup(udp_fd, 1) < 0 { return error_exit("cannot configure UDP socket") }
        link := new(Link)
        defer free_link(&link)
        start := time.tick_now()
        if !connect_link(udp, endpoint, &own, &peer, token, true, link, udp_fd) {
            return error_exit("cannot establish Noise session")
        }
        fmt.printfln("pong %v", time.tick_since(start))
        return 0
    }
    return 125
}

dial_local :: proc() -> c.int {
    sock_buffer: [1024]byte
    path := os.get_env(sock_buffer[:], "ECO_ODIN_SOCKET")
    when ODIN_OS == .Windows {
        if path == "" { path = default_pipe_name() }
    }
    if path == "" {
        home := eco_home()
        if home == "" { return -1 }
        path = fmt.tprintf("%s/socket", home)
    }
    if !valid_local_path(path) { return -1 }
    name := strings.clone_to_cstring(path, context.temp_allocator)
    fd := eco_connect_local(name)
    if fd >= 0 { return fd }

    address := os.get_env("ECO_ODIN_ADDR", context.temp_allocator)
    key := os.get_env("ECO_ODIN_KEY", context.temp_allocator)
    peer := client_peer(address)
    if address == "" || key == "" || peer == "" { return -1 }
    executable, err := os.get_executable_path(context.temp_allocator)
    if err != nil { return -1 }
    args: [7]cstring
    arguments := []string{executable, "client", path, address, key, peer}
    for arg, i in arguments {
        args[i] = strings.clone_to_cstring(arg, context.temp_allocator)
    }
    pid := eco_start_daemon(raw_data(args[:]))
    if pid < 0 { return -1 }
    deadline := time.tick_now()
    for time.tick_since(deadline) < 2*time.Second {
        fd = eco_connect_local(name)
        if fd >= 0 { return fd }
        time.sleep(5*time.Millisecond)
    }
    status: c.int
    _ = eco_child_poll(pid, &status)
    return -1
}

run_payload :: proc(args: []string, buf: []byte, tty: bool, rows, cols: u16) -> (result: []byte, ok: bool) {
    timeout := 60*60*1000
    cwd := "."
    with_input := tty
    i := 0
    for i < len(args) && args[i] != "--" {
        if args[i] == "--stdin" && !tty {
            with_input = true
            i += 1
            continue
        }
        if i+1 >= len(args) { return nil, false }
        switch args[i] {
        case "--cwd":
            cwd = args[i+1]
        case "--timeout-ms":
            value, valid := strconv.parse_int(args[i+1], 10)
            if !valid || value <= 0 || value > 24*60*60*1000 { return nil, false }
            timeout = value
        case:
            return nil, false
        }
        i += 2
    }
    if i+1 >= len(args) || cwd == "" || len(args)-i-1 > 64 || args[i+1] == "" { return nil, false }
    put_u32(buf, u32(timeout))
    buf[4] = 1 if with_input else 0
    encode_size(buf[5:9], rows, cols)
    n := 9
    if len(cwd)+1 > len(buf)-n { return nil, false }
    copy(buf[n:], cwd)
    n += len(cwd)+1
    for arg in args[i+1:] {
        if len(arg)+1 > len(buf)-n { return nil, false }
        copy(buf[n:], arg)
        n += len(arg)+1
    }
    return buf[:n], true
}

perform_upload :: proc(fd: c.int, input: ^os.File) -> bool {
    hasher: blake3.Hasher
    blake3.init(&hasher)
    buffer: [MESSAGE_MAX-1]byte
    for {
        n, err := os.read(input, buffer[:])
        if err != nil && err != .EOF { return false }
        if n == 0 { break }
        blake3.update(&hasher, buffer[:n])
        if !send_local(fd, .Upload, buffer[:n]) { return false }
    }
    digest := blake3.final(&hasher)
    return send_local(fd, .Commit, digest[:])
}

print_info :: proc(data: []byte) -> bool {
    if len(data) != 17 { return false }
    kind := "other"
    switch data[0] {
    case 0: kind = "missing"
    case 1: kind = "file"
    case 2: kind = "directory"
    }
    fmt.printfln("%s\t%d\t%d", kind, get_u64(data[1:]), get_u64(data[9:]))
    return true
}

command_cli :: proc(args: []string) -> int {
    command := args[0]
    op: Op
    path, local: string
    payload: []byte
    run_data: [MESSAGE_MAX-1]byte
    term_rows, term_cols: u16
    job_data: [MESSAGE_MAX-1]byte
    switch command {
    case "ping":
        if len(args) != 1 { return error_exit(USAGE) }
        op = .Ping
    case "start":
        rest := args[1:]
        if len(rest) >= 2 && rest[0] == "--id" {
            if !decode_key(rest[1], job_data[:JOB_ID]) { return error_exit("expected a 32-character job id") }
            rest = rest[2:]
        } else {
            random_bytes(job_data[:JOB_ID])
        }
        run, valid := run_payload(rest, job_data[JOB_ID:], false, 0, 0)
        if !valid || job_data[JOB_ID+4] != 0 { return error_exit(USAGE) }
        payload, op = job_data[:JOB_ID+len(run)], .Start
    case "attach", "kill":
        attaching := command == "attach"
        if len(args) != 2 && !(attaching && len(args) == 4) { return error_exit(USAGE) }
        if !decode_key(args[1], job_data[:JOB_ID]) { return error_exit("expected a 32-character job id") }
        size := JOB_ID
        if attaching {
            size += 16
            if len(args) == 4 {
                for value, i in args[2:] {
                    offset, valid := strconv.parse_int(value, 10)
                    if !valid || offset < 0 || offset > JOB_OUTPUT_MAX { return error_exit("invalid job offset") }
                    put_u64(job_data[JOB_ID+i*8:], u64(offset))
                }
            }
        }
        payload, op = job_data[:size], .Attach if attaching else .Kill
    case "jobs":
        if len(args) != 1 { return error_exit(USAGE) }
        op = .Jobs
    case "run", "tty":
        tty := command == "tty"
        if tty && eco_terminal_size(0, &term_rows, &term_cols) != 0 {
            return error_exit("tty requires an interactive local terminal")
        }
        var_ok: bool
        payload, var_ok = run_payload(args[1:], run_data[:], tty, term_rows, term_cols)
        if !var_ok { return error_exit(USAGE) }
        op = .Tty if tty else .Run
    case "get", "put":
        if len(args) != 3 { return error_exit(USAGE) }
        op = .Read if command == "get" else .Write
        path, local = args[1], args[2]
        if op == .Write { path, local = local, path }
        if bulk_enabled() { return bulk_client(op, path, local) }
    case:
        if len(args) != 2 { return error_exit(USAGE) }
        path = args[1]
        switch command {
        case "read":  op = .Read
        case "write": op = .Write
        case "stat":  op = .Stat
        case "list":  op = .List
        case "hash":  op = .Hash
        case "watch": op = .Watch
        case: return error_exit(USAGE)
        }
    }
    if op >= .Stat && op <= .Watch {
        if len(path) == 0 || len(path) >= MESSAGE_MAX { return error_exit("invalid path length") }
        payload = transmute([]byte)path
    }
    fd := dial_local()
    if fd < 0 { return error_exit("client unavailable; set ECO_ODIN_ADDR and ECO_ODIN_KEY, and pair with the server or set ECO_ODIN_PEER") }
    defer close_fd(&fd)

    input := os.stdin
    if op == .Write && local != "" {
        file, err := os.open(local)
        if err != nil { return error_exit("cannot open upload", err) }
        input = file
    }
    defer if input != os.stdin { _ = os.close(input) }
    output := os.stdout
    temp: string
    if op == .Read && local != "" {
        random: [16]byte
        random_bytes(random[:])
        temp = fmt.tprintf("%s.eco-part-%s", local, string(hex.encode(random[:], context.temp_allocator)))
        file, err := os.open(temp, {.Write, .Create, .Excl}, {.Read_User, .Write_User})
        if err != nil { return error_exit("cannot create download", err) }
        output = file
    }
    defer if temp != "" {
        if output != nil { _ = os.close(output) }
        _ = os.remove(temp)
    }

    if !send_local(fd, op, payload) { return error_exit("cannot send local request") }
    if (op == .Run || op == .Tty) && run_data[4] == 1 {
        return run_interactive(fd, op == .Tty, term_rows, term_cols)
    }

    buffer: [MESSAGE_MAX]byte
    hasher: blake3.Hasher
    if op == .Read { blake3.init(&hasher) }
    verified := false
    for {
        response := read_local(fd, buffer[:])
        if response == nil {
            if eco_stopping() != 0 { return 130 }
            return error_exit("connection lost; remote outcome may be unknown")
        }
        body := response[1:]
        #partial switch Op(response[0]) {
        case .Failure:
            return error_exit(string(body))
        case .Done:
            if len(body) != 4 { return error_exit("invalid exit status") }
            result := int(get_u32(body))
            if result != 0 { return result }
            if op == .Read && !verified { return error_exit("missing file digest") }
            if temp != "" {
                sync_err := os.sync(output)
                close_err := os.close(output)
                output = nil
                if sync_err != nil || close_err != nil || os.rename(temp, local) != nil {
                    return error_exit("cannot commit download")
                }
                temp = ""
            }
            if op == .Ping { fmt.println("pong") }
            return 0
        case .Info:
            if !print_info(body) { return error_exit("invalid metadata") }
        case .Entry:
            if op == .Jobs || op == .Start { fmt.println(string(body)) }
            else { fmt.printfln("%q", string(body)) }
        case .Stdout, .Stderr:
            if op == .Read { blake3.update(&hasher, body) }
            target := output if Op(response[0]) == .Stdout else os.stderr
            n, err := os.write(target, body)
            if err != nil || n != len(body) { return error_exit("cannot write output") }
        case .Digest:
            if len(body) != 32 { return error_exit("invalid file digest") }
            if op == .Hash {
                fmt.println(string(hex.encode(body, context.temp_allocator)))
            } else if op == .Read {
                digest := blake3.final(&hasher)
                if string(body) != string(digest[:]) { return error_exit("BLAKE3 verification failed") }
                verified = true
            }
        case .Ready:
            if op != .Write || !perform_upload(fd, input) { return error_exit("upload stopped") }
        case:
            return error_exit("unexpected response")
        }
    }
}

main :: proc() {
    eco_install_signals()
    load_bulk_limit()
    if len(os.args) < 2 { os.exit(error_exit(USAGE)) }
    args := os.args[1:]
    switch args[0] {
    case "help", "--help", "-h":
        fmt.print(USAGE)
    case "keygen":
        if len(args) != 2 { os.exit(error_exit(USAGE)) }
        os.exit(keygen(args[1]))
    case "issuer-keygen":
        if len(args) != 2 { os.exit(error_exit(USAGE)) }
        os.exit(issuer_keygen(args[1]))
    case "grant":
        os.exit(issue_capability(args[1:]))
    case "job-worker":
        if len(args) != 5 || (args[2] != "path" && args[2] != "scope") { os.exit(125) }
        os.exit(job_worker(args[1], args[3], args[4], args[2] == "scope"))
    case "forward", "forward-udp":
        if len(args) != 3 { os.exit(error_exit(USAGE)) }
        bind, bind_ok := net.parse_endpoint(args[1])
        target, target_ok := net.parse_endpoint(args[2])
        if !bind_ok || !target_ok || bind.port <= 0 || bind.port > 65535 || target.port <= 0 || target.port > 65535 {
            os.exit(error_exit("expected numeric IP:port for bind and target"))
        }
        os.exit(forward(bind, args[2], args[0] == "forward-udp"))
    case "serve", "client", "ping-early":
        os.exit(dispatch_platform(args))
    case "pair":
        if len(args) != 2 && len(args) != 3 { os.exit(error_exit(USAGE)) }
        name := args[2] if len(args) == 3 else os.get_env("COMPUTERNAME" when ODIN_OS == .Windows else "HOSTNAME", context.temp_allocator)
        os.exit(pair_client(args[1], name))
    case:
        os.exit(command_cli(args))
    }
}
