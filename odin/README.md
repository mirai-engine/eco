# ECO over Noise/UDP

ECO's Odin implementation uses a fixed `Noise_IK_25519_ChaChaPoly_BLAKE2s` suite and preconfigured
X25519 public keys. The local CLI talks to a small daemon over an owner-only Unix socket. The daemon
shares an authenticated UDP session across independent command, terminal, file and tunnel streams.
When the session rotates, streams on the previous session continue to receive keepalives.
The wire protocol uses binary records marked `ECO3`, and file transfers use BLAKE3. A
protocol change that breaks the wire format bumps the marker; peers of different versions do not
interoperate.

## Build and pair

The verified builds are macOS arm64 and Ubuntu 24.04 Linux arm64. Build with Odin containing
`core:crypto/noise` and `core:crypto/aegis` (tested with `dev-2026-10`; Windows builds need
`dev-2026-11` or newer, whose `wmain` entry point delivers arguments as UTF-8), a C toolchain and
Git. The
script fetches pinned KCP and odin-blake3 sources. On Linux, `pkg-config` and liburing development
headers enable the optional io_uring backend. All cryptography is Odin's; nothing links OpenSSL.

macOS uses poll for small descriptor sets and kqueue as they grow. Linux uses the same small-set
poll path and can use io_uring for larger sets when the kernel permits it. Set
`ECO_IO_URING=1` to exercise the ring even for small sets. With that override the server logs
`eco io_uring ready` after initializing the ring. Set `ECO_IO_URING=0` to use poll only.

The Odin daemon uses Noise, binary framing and pinned keys.

```sh
./odin/build.sh
bin/eco keygen server.key  # run on the server machine
bin/eco keygen client.key  # run on the client machine
```

Leave the private files on their respective machines. The server accepts the clients in its
`CLIENTS` trust store, which it reads on every handshake, so a revocation applies to the client's
next session. Pairing fills both sides without copying keys:

```sh
# Server, with native read/write, command execution, PTY and forwarding enabled
mkdir -m 700 "$HOME/.eco-jobs"
ECO_JOBS="$HOME/.eco-jobs" \
  bin/eco serve 192.0.2.10:8443 server.key clients /path/to/repo run

# Client
export ECO_ADDR=192.0.2.10:8443
export ECO_KEY="$PWD/client.key"
bin/eco pair "$ECO_ADDR" laptop
bin/eco ping
```

Both screens show the same verification code, for example `0346-9283`. Pairing runs a
`Noise_XX` handshake in which the client first commits to its static key and a fresh nonce, and
opens the commitment only after the server has sent its own nonce; the server rejects a client
whose opening does not match before it shows a code. The code hashes both ephemeral keys, both
static keys and both nonces, and nothing a sender can choose after seeing the other side's nonce,
such as the names either side shows. A machine in the middle must fix its half of each code before
it learns the nonce that completes it, so it matches the two screens with probability 10⁻⁸ per
attempt. A running server always accepts requests and asks its operator: on
Windows and macOS a dialog in the operator's session shows the client's name, address and code,
with No as the default; on Linux the server's terminal asks `y` or `n`. A request expires after
five minutes. On approval the server adds the client to `CLIENTS` and the client stores the
server key under its address in the `ECO_HOME/servers` trust store (`~/.eco` by default), which
later commands use for that `ECO_ADDR`; `ECO_PEER` pins a key instead.

Any machine that reaches the port can raise a request, so approve only one you expect and whose
code matches. The server handles one request at a time and, after five denied or expired requests
in a row, ignores new ones for ten minutes. A client that does not open its commitment counts as a
denial. The code has 8 digits.

### Trust stores

`CLIENTS` and `ECO_HOME/servers` are binary trust stores. Each entry holds a public key, a label, the
time it was added, an optional expiry and a revoked flag; a BLAKE3 digest covers the whole file, and
a store that is malformed, truncated or of another version authorizes nothing. Every change writes
a private temporary file, syncs it and renames it over the store. A key lookup compares every entry
in constant time.

```sh
eco trust add clients CLIENT_PUBLIC laptop        # optional lifetime in seconds after the label
eco trust revoke clients CLIENT_PUBLIC
eco trust list clients                            # key, label, added, expiry, state
```

The client starts its daemon on demand and exits it after two minutes without local calls.
Alternatively, run `eco client SOCKET UDP KEY PEER` in the foreground. Use a separate
`ECO_SOCKET` in an owner-only directory for each distinct server, identity or capability.
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
eco stat path
eco list .
eco watch path
eco hash path
eco read path
eco put ./local.bin target.bin
eco get target.bin ./verified.bin
eco run --cwd subdir -- git status --short
eco run --stdin -- /usr/bin/cat
eco run --sh --cwd subdir -- 'make -j8 && printf "%s\n" "$1"' done
eco tty -- /bin/sh
eco forward 127.0.0.1:8765 127.0.0.1:8765
eco forward-udp 127.0.0.1:5354 127.0.0.1:5353

job=$(eco start -- /usr/bin/make)
eco jobs
eco attach "$job"
eco attach "$job" 128 0  # resume at these stdout and stderr byte offsets
eco kill "$job"
```

`run`, `tty` and `start` accept command arguments and a working directory totaling up to
128 KiB of encoded request data. The remote operating system can impose a smaller limit.
`run` automatically forwards piped or redirected stdin; pass `--stdin` to force forwarding or
`--no-stdin` to close remote stdin immediately. `run`, `tty` and `start` start the program
directly, without a shell. With `--sh`, the first word after `--` is a script for the server's
POSIX shell and the rest are its positional parameters `$1`, `$2`...; `$0` is `sh`. The shell is
`/bin/sh` on macOS and Linux and Git Bash on Windows, and it reads no profile.
A command's timeout includes draining its output. A responsive stream stays open even while a command produces no output.
Windows exit codes above 255 are printed in hexadecimal. On macOS and Linux
the CLI returns 125 for those codes because the local process status has only eight bits.

File paths are relative to the server root or the granted subdirectory. Native operations walk
directory descriptors and reject symlink traversal. Uploads are verified before atomic replacement.
Downloads verify their whole BLAKE3 digest before replacing the local destination. `watch` samples
metadata every 250 ms and detects changes visible at the sampling boundary.

Set `ECO_BULK_TCP=1` on both machines to send `put` and `get` over a separate TCP listener
on the same numeric port. The bulk client uses `ECO_ADDR`, `ECO_KEY`, `ECO_PEER`
and, when required, `ECO_CAPABILITY`. The Noise IK handshake uses a distinct prologue, and
a transport-encrypted confirmation carries fresh keying material. HKDF-SHA256 binds it to the
Noise transcript, and separate AEGIS-256 keys authenticate the two record directions, with the
record counter as the nonce. Odin's AEGIS uses the CPU's AES instructions where present and a
constant-time portable implementation elsewhere. The server starts a transfer worker only after it
verifies that confirmation.

The remote target of a forward is a numeric IP and port as seen by the server. TCP forwarding
bridges two TCP connections over a KCP stream and preserves half-close. UDP forwarding preserves
datagram boundaries over a KCP stream, with a 1,135-byte application datagram limit and a bounded
queue per sender.

`start --id HEX` accepts a 32-character idempotency key. A detached worker owns the process and
spools stdout, stderr and the exit status to disk. `attach` works across server and client daemon
restarts. A worker that exits without publishing a result leaves an indeterminate job and the server
does not rerun it. When `serve ... run` starts without `ECO_JOBS` set, Eco uses a private
`ECO_HOME/jobs` directory automatically; set `ECO_JOBS=` (empty) to disable background jobs.
Jobs retain at most 64 MiB per output stream and remain on disk until the operator removes them.
A machine reboot can terminate the workers themselves.

## Adapters for agents and tools

First-party tools use the ECO CLI or binary IPC for native operations. To try a third-party ACP
agent or MCP server over stdio, configure its client to launch
`eco run --stdin -- PROGRAM ARGS...`. The two ends still speak their original protocol.
For a third-party MCP server using Streamable HTTP, use `eco forward` and point the MCP client
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
ECO_DESKTOP_SOCKET="$HOME/.eco-desktop/helper.sock" \
  bin/eco serve SERVER_IP:8443 server.key clients /path/to/repo run
```

After [pairing](#build-and-pair), use the normal client CLI on the controlling machine.

```sh
bin/eco desktop capture > screen.jpg
bin/eco desktop click 150 80
bin/eco desktop type 'Hello'
bin/eco desktop stream 4 | ffplay -f mjpeg -i -
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

A video datagram is an authenticated ECO3 record in the existing Noise session. Its plaintext
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
eco issuer-keygen issuer.key  # keep this file on the granting machine
eco grant issuer.key SERVER_PUBLIC CLIENT_PUBLIC r 3600 subdir
# Add ISSUER_PUBLIC after the server access mode. On the client:
export ECO_CAPABILITY=SIGNED_GRANT_FROM_PREVIOUS_COMMAND
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
  `ECO_BULK_MBPS` on each sending daemon to match the available rate in megabits per second.
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
cancel process trees. A process created with `CREATE_BREAKAWAY_FROM_JOB`, such as a detached
server or editor that a command starts, leaves the tree and outlives the command; the client
daemon and job workers break away from a job that Eco itself runs in when that job allows it.
Project-relative native file operations reject NTFS reparse points.
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

Both builds produce `bin/eco.exe`. The cross build refuses an Odin whose Windows entry point is
`main`, which receives arguments in the ANSI code page and mangles non-ASCII paths.

ECO on Windows requires [Git for Windows](https://git-scm.com/download/win). `serve ... run`
refuses to start without it, and `--sh` scripts run with its Git Bash (`Git\bin\bash.exe`, found
from `git.exe` on `PATH` or in the machine or per-user install folder), never with WSL's
`System32\bash.exe`. Git Bash parses its command line through the MSYS2 runtime, which expands
wildcards and truncates long quoted words, so the server passes the script and its parameters as
escaped words that a short prelude decodes; they arrive byte for byte. On Windows, the default IPC
endpoint is
`\\.\pipe\eco-<current-user-SID>`. For a second daemon, set `ECO_SOCKET` to a
different local pipe name, such as `\\.\pipe\eco-work`. Set `ECO_ADDR` and
`ECO_KEY`, and pair, as on Unix. Key generation creates a private ACL.
The job directory must be on NTFS and owned by the launching user with an ACL scoped to
that user and trusted system administrators. Eco creates `ECO_HOME/jobs` and the namespace of
each client inside the job directory with an ACL of that user and SYSTEM that the jobs inherit.

From any client, a single program runs directly and a sequence of commands runs as a Git Bash
script, never through PowerShell or `cmd.exe` quoting:

```sh
eco run -- git.exe -C C:/src/project status --short
eco run --sh -- 'cd C:/src/project && git pull --ff-only && ./build.sh'
eco forward 127.0.0.1:7940 127.0.0.1:7940
```

The Windows smoke suite runs on a native host. It exercises identity, IOCP IPC, binary I/O,
ConPTY resize, reparse-point rejection, files over UDP and TCP, `--sh` scripts through Git Bash
with hostile parameters, forwarding, reattaching to a
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
