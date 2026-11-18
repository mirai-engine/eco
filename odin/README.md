# ECO over Noise/UDP

ECO's Odin implementation uses a fixed `Noise_IK_25519_ChaChaPoly_BLAKE2s` suite and preconfigured
X25519 public keys. The local CLI talks to a small daemon over an owner-only Unix socket. The daemon
shares one authenticated UDP session across independent command, terminal, file and tunnel streams.
The wire protocol uses binary records, and file transfers use BLAKE3.

## Build and pair

The verified build targets macOS arm64. It uses Odin with `core:crypto/noise` (tested with
`dev-2026-10` at `05d3fbf34`), a C toolchain and Git. The script fetches the pinned KCP and
odin-blake3 sources on the first build. The POSIX layer uses poll for small descriptor sets and switches to kqueue on macOS as they grow.
The Odin runtime path has no dependency on Go, SSH, TLS or a certificate authority.

```sh
./odin/build.sh
bin/eco-odin keygen server.key  # run on the server machine
bin/eco-odin keygen client.key  # run on the client machine
```

Exchange the printed public keys over an authenticated channel. Leave the private files on their
respective machines. The server pins one client public key per listener.

```sh
# Server, with native read/write, command execution, PTY and forwarding enabled
mkdir -m 700 "$HOME/.eco-odin-jobs"
ECO_ODIN_JOBS="$HOME/.eco-odin-jobs" \
  bin/eco-odin serve 192.0.2.10:8443 server.key CLIENT_PUBLIC /path/to/repo run

# Client
export ECO_ODIN_ADDR=192.0.2.10:8443
export ECO_ODIN_KEY="$PWD/client.key"
export ECO_ODIN_PEER=SERVER_PUBLIC
bin/eco-odin ping
```

The client starts its daemon on demand and exits it after two minutes without local calls.
Alternatively, run `eco-odin client SOCKET UDP KEY PEER` in the foreground. Use a separate
`ECO_ODIN_SOCKET` in an owner-only directory for each distinct server, identity or capability.
An existing daemon keeps its original settings until it exits.

## Operations

```sh
eco-odin stat path
eco-odin list .
eco-odin watch path
eco-odin hash path
eco-odin read path
eco-odin put ./local.bin target.bin
eco-odin get target.bin ./verified.bin
eco-odin run --cwd subdir -- git status --short
eco-odin run --stdin -- /usr/bin/cat
eco-odin tty -- /bin/sh
eco-odin forward 127.0.0.1:8765 127.0.0.1:8765
eco-odin forward-udp 127.0.0.1:5354 127.0.0.1:5353

job=$(eco-odin start -- /usr/bin/make)
eco-odin jobs
eco-odin attach "$job"
eco-odin attach "$job" 128 0  # resume at these stdout and stderr byte offsets
eco-odin kill "$job"
```

File paths are relative to the server root or the granted subdirectory. Native operations walk
directory descriptors and reject symlink traversal. Uploads are verified before atomic replacement.
Downloads verify their whole BLAKE3 digest before replacing the local destination. `watch` samples
metadata every 250 ms. It can miss changes between samples.

The remote target of a forward is a numeric IP and port as seen by the server. TCP forwards preserve
half-close. UDP forwards have a 1,135-byte application datagram limit and a bounded queue per sender.
For MCP over stdio, configure the client to launch `eco-odin run --stdin -- PROGRAM ARGS...`.
For Streamable HTTP, keep an `eco-odin forward` open and point the MCP client at the local endpoint.

`start --id HEX` accepts a 32-character idempotency key. A detached worker owns the process and
spools stdout, stderr and the exit status to disk. `attach` works across server and client daemon
restarts. A worker that exits without publishing a result leaves an indeterminate job and the server
does not rerun it. Jobs require an explicit store, retain at most 64 MiB per output stream and remain
on disk until the operator removes them. A machine reboot can terminate the workers themselves.

## Capability grants

The listener defaults to `read`. Set `write` to enable writes, `tunnel` for forwarding or `run` for
full access. Add an Ed25519 issuer public key as the last argument to require a signed grant in
addition to the pinned client identity.

```sh
eco-odin issuer-keygen issuer.key  # keep this file on the granting machine
eco-odin grant issuer.key SERVER_PUBLIC CLIENT_PUBLIC r 3600 subdir
# Add ISSUER_PUBLIC after the server access mode. On the client:
export ECO_ODIN_CAPABILITY=SIGNED_GRANT_FROM_PREVIOUS_COMMAND
```

A grant binds the server and client identities, expiry, operations and directory. The letters are
`r` for file reads and metadata, `w` for writes, `x` for processes and jobs, and `t` for forwarding.
The server mode and grant both apply. Process and forwarding grants require the full-root scope
`.`. A process runs with the daemon account's privileges and is not confined by the file path grant.
Forwarding targets are reachable wherever the daemon account can connect.

## Transport behavior

- Each datagram starts with a 24-byte header containing the protocol marker, record kind, 64-bit
  session ID and 64-bit nonce. The header is authenticated as additional data after Noise split.
- The first Noise message can request a ping. An observer can replay that message. Commands, writes,
  jobs and tunnels require authenticated post-handshake traffic.
- Transport records have a 512-packet replay window and fit within a 1,200-byte UDP payload. A
  challenge-response verifies a new return path before changing the session endpoint.
- Each active stream uses KCP for selective retransmission and flow control. Congestion windows
  are per stream. There is no connection-wide pacing or separate bulk path. A transfer or command
  can keep streaming while another stream recovers from packet loss.
- The server expires idle sessions and rotates them within 15 minutes. Clients keep an idle session
  warm while the local daemon runs. On a lost session, an in-flight call can have an unknown result.
  Use detached jobs and their explicit IDs when restart recovery matters.

The current implementation uses bounded copies in the framing and retransmission paths. The Odin
port has no Windows backend yet. ConPTY, IOCP, Windows Named Pipes and a Linux io_uring backend
remain outside this build. The macOS tests do not validate the POSIX fallback on Linux.

## Verify and measure

```sh
./odin/build.sh
./odin/build.sh test
python3 -B odin/smoke.py
python3 -B odin/extended_test.py
python3 -B odin/bench.py --bulk-mib 8
```

The loopback tests cover binary files, verified atomic replacement, concurrent streams, terminal
resize, stdin, both types of forwarding, signed scopes, replay and corruption handling, source-port
migration, and job recovery after restarting both daemons. The benchmark reports CLI launch
separately from warm requests made directly over the daemon's Unix socket.
