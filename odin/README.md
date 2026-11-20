# ECO over Noise/UDP

ECO's Odin implementation uses a fixed `Noise_IK_25519_ChaChaPoly_BLAKE2s` suite and preconfigured
X25519 public keys. The local CLI talks to a small daemon over an owner-only Unix socket. The daemon
shares an authenticated UDP session across independent command, terminal, file and tunnel streams.
When the session rotates, streams on the previous session continue to receive keepalives.
The wire protocol uses binary records, and file transfers use BLAKE3.

## Build and pair

The verified builds are macOS arm64 and Ubuntu 24.04 Linux arm64. Build with Odin containing
`core:crypto/noise` (tested with `dev-2026-10`), a C toolchain and Git. The script fetches pinned KCP
and odin-blake3 sources. On Linux, `pkg-config` and liburing development headers enable the optional
io_uring backend. On both platforms, `pkg-config` and libcrypto development headers enable bulk
AES-GCM acceleration.

macOS uses poll for small descriptor sets and kqueue as they grow. Linux uses the same small-set
poll path and can use io_uring for larger sets when the kernel permits it. Set
`ECO_ODIN_IO_URING=1` to exercise the ring even for small sets. With that override the server logs
`eco-odin io_uring ready` after initializing the ring. Set `ECO_ODIN_IO_URING=0` to use poll only.

The Odin daemon uses Noise, binary framing and pinned keys.

```sh
./odin/build.sh
bin/eco-odin keygen server.key  # run on the server machine
bin/eco-odin keygen client.key  # run on the client machine
```

Leave the private files on their respective machines. The server accepts the clients listed in a
`CLIENTS` file, one public key per line followed by an optional label; it reads the file on every
handshake, so deleting a line revokes that client for its next session. Pairing fills both sides
without copying keys:

```sh
# Server, with native read/write, command execution, PTY and forwarding enabled
mkdir -m 700 "$HOME/.eco-odin-jobs"
ECO_ODIN_JOBS="$HOME/.eco-odin-jobs" \
  bin/eco-odin serve 192.0.2.10:8443 server.key clients /path/to/repo run

# Client
export ECO_ODIN_ADDR=192.0.2.10:8443
export ECO_ODIN_KEY="$PWD/client.key"
bin/eco-odin pair "$ECO_ODIN_ADDR" laptop
bin/eco-odin ping
```

Both screens show the same verification code, for example `0346-9283`. It is derived from the
transcript of a `Noise_XX` handshake, which binds both static keys, so a machine in the middle
makes the two codes differ. A running server always accepts requests and asks its operator: on
Windows and macOS a dialog in the operator's session shows the client's name, address and code,
with No as the default; on Linux the server's terminal asks `y` or `n`. A request expires after
five minutes. On approval the server appends the client to `CLIENTS` and the client stores the
server key under its address in `ECO_ODIN_HOME/known_servers` (`~/.eco-odin` by default), which
later commands use for that `ECO_ODIN_ADDR`; `ECO_ODIN_PEER` pins a key instead.

Any machine that reaches the port can raise a request, so approve only one you expect and whose
code matches. The server handles one request at a time and, after five denied or expired requests
in a row, ignores new ones for ten minutes. The code has 8 digits.

The client starts its daemon on demand and exits it after two minutes without local calls.
Alternatively, run `eco-odin client SOCKET UDP KEY PEER` in the foreground. Use a separate
`ECO_ODIN_SOCKET` in an owner-only directory for each distinct server, identity or capability.
An existing daemon keeps its original settings until it exits.

For reusable local queries, connect directly to that Unix socket. Each frame starts with a
two-byte little-endian length followed by an opcode byte and its body. Send opcode 23 with
an empty body to start a reusable session and wait for opcode 39. Send ping (1, empty body)
or stat (2, relative path bytes) serially. A stat response carries metadata (35, type byte
and two little-endian uint64 values for size and mtime in nanoseconds). Both operations end
with 37 and a zero 32-bit status, or 38 and an error message. The client and server use an
authenticated request/reply record, with retries for loss, for these read-only operations.

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

`run`, `tty` and `start` accept command arguments and a working directory totaling up to
128 KiB of encoded request data. The remote operating system can impose a smaller limit.
`run` automatically forwards piped or redirected stdin; pass `--stdin` to force forwarding or
`--no-stdin` to close remote stdin immediately. A command's timeout includes draining
its output. A responsive stream stays open even while a command produces no output.
Windows exit codes above 255 are printed in hexadecimal. On macOS and Linux
the CLI returns 125 for those codes because the local process status has only eight bits.

File paths are relative to the server root or the granted subdirectory. Native operations walk
directory descriptors and reject symlink traversal. Uploads are verified before atomic replacement.
Downloads verify their whole BLAKE3 digest before replacing the local destination. `watch` samples
metadata every 250 ms and detects changes visible at the sampling boundary.

Set `ECO_ODIN_BULK_TCP=1` on both machines to send `put` and `get` over a separate TCP listener
on the same numeric port. The bulk client uses `ECO_ODIN_ADDR`, `ECO_ODIN_KEY`, `ECO_ODIN_PEER`
and, when required, `ECO_ODIN_CAPABILITY`. The Noise IK handshake uses a distinct prologue, and
a transport-encrypted confirmation carries fresh keying material. HKDF-SHA256 binds it to the
Noise transcript, and separate AES-256-GCM keys authenticate the two record directions. The
server starts a transfer worker only after it verifies that confirmation. Libcrypto loads on
demand when available. `ECO_ODIN_BULK_CRYPTO=portable` selects the wire-compatible Odin AES
implementation. Each bulk connection is bounded to 2²² records per direction.

The remote target of a forward is a numeric IP and port as seen by the server. TCP forwarding
bridges two TCP connections over a KCP stream and preserves half-close. UDP forwarding preserves
datagram boundaries over a KCP stream, with a 1,135-byte application datagram limit and a bounded
queue per sender.

`start --id HEX` accepts a 32-character idempotency key. A detached worker owns the process and
spools stdout, stderr and the exit status to disk. `attach` works across server and client daemon
restarts. A worker that exits without publishing a result leaves an indeterminate job and the server
does not rerun it. When `serve ... run` starts without `ECO_ODIN_JOBS` set, Eco uses a private
`ECO_ODIN_HOME/jobs` directory automatically; set `ECO_ODIN_JOBS=` (empty) to disable background jobs.
Jobs retain at most 64 MiB per output stream and remain on disk until the operator removes them.
A machine reboot can terminate the workers themselves.

## Adapters for agents and tools

First-party tools use the ECO CLI or binary IPC for native operations. To try a third-party ACP
agent or MCP server over stdio, configure its client to launch
`eco-odin run --stdin -- PROGRAM ARGS...`. The two ends still speak their original protocol.
For a third-party MCP server using Streamable HTTP, use `eco-odin forward` and point the MCP client
at the local endpoint.

## Desktop control

The desktop host needs macOS 14 or later. Run the helper and the ECO server as the same logged-in
user. After building ECO, build and start the helper from that user's graphical session.

```sh
./odin/build.sh desktop
mkdir -p -m 700 "$HOME/.eco-desktop"
bin/eco-desktop --request-permissions
bin/eco-desktop "$HOME/.eco-desktop/helper.sock"
```

macOS controls Screen Recording and Accessibility. Enable both for the helper or its launching app
as indicated by macOS, then relaunch the helper if prompted. Start the ECO server in its own shell.

```sh
ECO_ODIN_DESKTOP_SOCKET="$HOME/.eco-desktop/helper.sock" \
  bin/eco-odin serve SERVER_IP:8443 server.key clients /path/to/repo run
```

After [pairing](#build-and-pair), use the normal client CLI on the controlling machine.

```sh
bin/eco-odin desktop capture > screen.jpg
bin/eco-odin desktop click 150 80
bin/eco-odin desktop type 'Hello'
bin/eco-odin desktop stream 4 | ffplay -f mjpeg -i -
```

`move X Y` and `click X Y [left|right]` use pixels in the returned image, with origin at the
top left. The helper captures the main display and scales the longest side to at most 960 pixels.
`key CODE` presses and releases a macOS virtual key. `scroll DX DY` takes signed pixel deltas.
Clicks and keys send paired down/up events. Use Mirai's API for scene operations and viewport
capture.

The daemon talks to the helper over an owner-only Unix socket using a 32-bit little-endian length
followed by a binary request or response. Desktop calls require unconfined execution in the existing
`run` mode. Snapshots and input travel on reliable ECO streams. The stream command yields
concatenated JPEGs, defaults to 4 FPS, and accepts a capture rate from 1 to 10 FPS. One video stream
may run per host and Ctrl-C cancels it. Video is paced at up to four datagrams per 10 ms after
reliable traffic has been serviced.

A video datagram is an authenticated ECO2 record in the existing Noise session. Its plaintext
starts with the stream ID (`u32`), frame ID (`u32`), zero-based chunk index (`u16`) and chunk count
(`u16`), all little-endian. Each chunk holds up to 1,148 bytes of a JPEG, for at most 1,200 bytes of
UDP payload including ECO and Noise overhead. The JPEG is capped at 256 KiB. The receiver accepts
out-of-order chunks within a frame, discards incomplete frames when a newer frame starts, and
rejects fragments for frames older than one second from their first chunk. JPEGs are independent, so
the next complete image can be displayed immediately after loss.

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
The server mode and grant both apply. Forwarding grants use the full-root scope `.`, and targets
are reachable wherever the daemon account can connect.

On Linux with Landlock ABI 3 or newer, an `x` grant can target a subdirectory. Run, PTY and
detached jobs inherit that directory boundary. They can read system tool directories, write
inside the granted project, and receive a minimal environment. A seccomp filter denies creation
of network sockets and access to selected host-wide interfaces. This is filesystem and process
confinement for builds with local dependencies. It does not impose CPU or disk quotas.
Systems that cannot enforce the scope reject a scoped execution request. An explicit `x` grant
for the full root `.` uses the daemon account's ordinary privileges. Signed job lifetimes also
respect the grant expiry. The job namespace binds to the client identity and granted directory.

## Transport behavior

- Each datagram starts with a 24-byte header containing the protocol marker, record kind, 64-bit
  session ID and 64-bit nonce. The header is authenticated as additional data after Noise split.
- The first Noise message can request a ping. An observer can replay that message. Commands, writes,
  jobs and tunnels require authenticated post-handshake traffic.
- Transport records have a 512-packet replay window and fit within a 1,200-byte UDP payload. A
  challenge-response verifies a new return path before changing the session endpoint.
- Each active stream uses KCP for selective retransmission and flow control. Congestion windows
  are per stream. A shared byte budget paces large UDP file records across streams. Set
  `ECO_ODIN_BULK_MBPS` on each sending daemon to match the available rate in megabits per second.
  The default budget is 10,000 Mbps. Control and acknowledgment records can pass queued file data.
- Clients open a fresh session for new calls before the 15-minute limit on opening streams.
  Existing streams finish on their original session, subject to inactivity and signed grant
  expiration. Clients keep an idle session warm while the local daemon runs. On a lost session,
  an in-flight call can have an unknown result. Use detached jobs and their explicit IDs when
  restart recovery matters.

The current implementation uses bounded copies in the framing and retransmission paths.
The Windows backend targets x64 Windows 10 version 1809 or newer, including Windows 11.
Named Pipes use IOCP for asynchronous reads, writes and accepts. Winsock notifications wake
the same completion loop. Windows uses ConPTY for terminal sessions and Job Objects to
cancel process trees. Project-relative native file operations reject NTFS reparse points.
Windows rejects execution grants scoped to a subdirectory. Landlock confinement is Linux-only.

### Build and run on Windows

Run the native build from an x64 Visual Studio developer shell with Odin, Git and a recent
Windows SDK.

```powershell
.\odin\build-windows.ps1
py -3 .\odin\windows_smoke.py
```

Cross-compile on macOS or Linux with a matching LLVM-MinGW UCRT toolchain.

```sh
./odin/build-windows-cross.sh /absolute/path/to/llvm-mingw/bin
```

Both builds produce `bin/eco-windows-amd64.exe`. On Windows, the default IPC endpoint is
`\\.\pipe\eco-odin-<current-user-SID>`. For a second daemon, set `ECO_ODIN_SOCKET` to a
different local pipe name, such as `\\.\pipe\eco-odin-work`. Set `ECO_ODIN_ADDR` and
`ECO_ODIN_KEY`, and pair, as on Unix. Key generation creates a private ACL.
The job directory must be on NTFS and owned by the launching user with an ACL scoped to
that user and trusted system administrators.

```powershell
.\bin\eco-windows-amd64.exe run -- cmd.exe /d /c ver
.\bin\eco-windows-amd64.exe tty -- powershell.exe -NoLogo
```

The Windows smoke suite runs on a native host. It exercises identity, IOCP IPC, binary I/O,
ConPTY resize, reparse-point rejection, files over UDP and TCP, forwarding, reattaching to a
detached job, and pairing through the approval dialog with denial, approval and revocation.

## Verify and measure

```sh
./odin/build.sh
./odin/build.sh test
python3 -B odin/smoke.py
python3 -B odin/extended_test.py
python3 -B odin/desktop_test.py
python3 -B odin/bench.py --bulk-mib 8
python3 -B odin/compare.py
```

The loopback tests cover binary files, verified atomic replacement, concurrent streams, terminal
resize, stdin, both types of forwarding, signed scopes, replay and corruption handling, source-port
migration, scoped builds on Linux, encrypted bulk transfers and job recovery after restarting
both daemons. The comparison interleaves ECO and a local OpenSSH instance with
temporary credentials. It reports CLI launch separately from warm requests and validates each
download independently.
