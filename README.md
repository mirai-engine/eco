# eco

The [Odin Noise/UDP implementation](odin/README.md) provides a binary protocol, native file
operations, a persistent local client, POSIX terminals, tunnels and durable jobs. Its verified
builds are macOS arm64 and Ubuntu Linux arm64. A native Windows x64 backend builds through
cross-compilation. The rest of this README describes the Go TLS implementation.

Experimental remote command transport for agents. One TLS 1.3 connection carries many concurrent
commands, file transfers and pings as multiplexed binary streams, and survives network drops without
running anything twice.

An authenticated client can execute arbitrary programs with the server user's privileges. The server is
not a sandbox; bind to a private address and restrict access at the firewall.

## Build

```sh
go build -o eco ./cmd/eco
GOOS=windows GOARCH=amd64 go build -o eco.exe ./cmd/eco
```

## Pairing (no files to copy)

Each machine creates its own identity (`key.pem`, `cert.pem`) in `~/.eco` (`%USERPROFILE%\.eco` on
Windows; override with `--dir` or `ECO_HOME`) the first time it is used. Trust is established once, like
SSH `known_hosts` plus `authorized_keys`, but with an explicit approval on the server.

On the server (keep this window open, it asks for approval):

```sh
eco serve --addr SERVER_IP:8443 --pair
```

On the client:

```sh
eco pair --addr SERVER_IP:8443
```

Both screens show the same verification code, for example `0346-9283`. The code is derived from the TLS
session and from both identities, so a machine in the middle makes the two codes differ. Compare them and
approve on the server: answer `y` or `yes` in its terminal (`n` or `no` denies; any other answer asks
again), or click Yes in the dialog that Windows servers also show. The request
waits 5 minutes. The server stores the client fingerprint in `authorized_clients`; the client stores the
server fingerprint in `known_servers`. From then on no approval is needed.

- `--pair` is only needed while adding machines. Without it, unknown clients are refused. Restart the
  server without `--pair` once everything is paired.
- One pairing at a time; after 5 denied or timed-out attempts pairing locks until the server restarts.
  Pairing again from an already authorized client (for example through another IP) is approved the same way.
- The code has 8 digits (about 27 bits). It protects against passive and naive active attackers on a LAN,
  not against an attacker able to grind many handshakes before you answer; answer only when you expect a
  request.
- To revoke a client, delete its line from `authorized_clients` (read on every connection). If a server's
  fingerprint changes, clients refuse to connect until you run `eco pair` again.
- The client label shown on the server (`--name`) is chosen by the client; trust the fingerprint and code,
  not the label.

## Commands

`--addr HOST:PORT` can be omitted when only one server is paired, or set once with `ECO_ADDR`.

```sh
eco run [--cwd DIR] [--timeout 30s] [--env K=V] [--job ID] [--wait 50s] [--stdin] -- program args...
eco start [--cwd DIR] [--env K=V] [--job ID] -- program args...   # prints the job id
eco attach JOB [--wait 50s] [--all]
eco jobs [--json]
eco kill JOB
eco cat REMOTE
eco write REMOTE < content
eco put LOCAL REMOTE
eco get REMOTE LOCAL
eco forward [LADDR:]LPORT:HOST:PORT
eco ping
eco connect                    # JSON lines for programs, see below
```

- `run` streams stdout and stderr to the local ones and exits with the remote exit code. Ctrl-C kills the
  remote process tree. Without `--stdin` the command is durable: if the connection drops, `run` reconnects
  and continues where it left off.
- `run --wait D` stops waiting after D and exits with status **254**, printing the job id; the command
  keeps running. `start` does the same immediately. `attach JOB` prints the output no client has received
  yet and then mirrors the exit code (or exits 254 again after `--wait`); `--all` replays all retained
  output. Ctrl-C on `attach` only detaches; `kill` stops the job and its process tree. `jobs` lists running
  jobs and finished ones from the last hour.
- A command is finished when its process exits. Programs it launched in the background (`Start-Process`,
  `cmd &`, daemons) keep running but no longer hold `run` open, even if they inherited its output.
- `cat` prints a remote file; `write` stores stdin as a remote file. Both are byte-exact (no shell quoting
  or encoding in between) and SHA-256 verified; `write` replaces the file atomically.
- `put` writes to `REMOTE.eco-part` and renames after verifying size and SHA-256, so the destination is never
  half written. `get` verifies the SHA-256 of the whole file and resumes from `LOCAL.eco-part` if a previous
  download was interrupted; a partial that fails verification is discarded.
- `forward 8765:127.0.0.1:8765` listens on local port 8765 and relays each connection to `127.0.0.1:8765`
  as seen from the server, so services that only listen on the server's loopback (an MCP server, a dev
  server, a database) are reachable from the client. Like `ssh -L`.

## Using eco from an agent

Agent harnesses kill tool calls after a time limit. Call eco directly (no wrapper scripts or base64) and
keep every call under that limit:

```sh
eco run --wait 50s --cwd 'C:\work\repo' -- powershell -NoProfile -Command 'cargo build'
# exit 254 means "still running"; continue with:
eco attach JOB --wait 50s
```

- Long builds: `eco start -- ...`, then `eco attach JOB --wait 50s` until it exits. No `Start-Process`,
  log files or process polling needed. If the harness kills eco anyway, the job keeps running and `attach`
  replays everything it has not confirmed as delivered.
- Editing remote files: `eco cat PATH` to read, `eco write PATH` with the new content on stdin (a heredoc
  works), or `eco get` / `eco put` to edit a local copy.
- Tools that only listen on the server (for example an MCP server on `127.0.0.1`): `eco forward` and point
  the agent at the local port.

## Session for programs: `eco connect`

Reads one JSON request per line from stdin and writes one JSON event per line to stdout. Requests run
concurrently over one connection; events of different ids may interleave, events of one id are ordered.

```json
{"id":"1","method":"exec","executable":"git","args":["status","--short"],"cwd":"C:\\work","timeout_ms":60000}
{"id":"2","method":"exec","executable":"findstr","args":["x"],"stdin":true}
{"id":"2","method":"stdin","data":"eHh4Cg==","eof":true}
{"id":"1","method":"cancel"}
{"id":"3","method":"ping"}
```

Events: `started`, `stdout` / `stderr` (`data` is base64 on this local pipe only; the network carries raw
bytes), `exit` (`exit_code`, and `error` set to `canceled`, `timeout`, ... when the command was stopped),
`pong`, `error`. Ids must be unique per session. When stdin closes, `connect` waits for running commands
and exits.

## Behavior

- **Concurrency.** Commands, transfers and pings are independent streams; a slow consumer on one stream
  does not block the others (per-stream credit flow control, 4 MiB window).
- **Output.** Stdout and stderr are separate and unbounded in size. Output is raw bytes; there is no
  base64 or per-command cap on the network.
- **Durable jobs.** Commands run through `run` or `connect` (without stdin) carry a job id. If the
  connection drops, the server keeps the process running and buffers up to 16 MiB of output per stream;
  the client reconnects, presents the same job id and the number of bytes it already has, and receives the
  rest exactly once. Presenting a job id again never starts the command a second time, so a retry after an
  ambiguous failure is safe. Finished jobs stay available for an hour. Jobs from `run` and `start` keep
  running with nobody attached until they end; jobs from `connect` are killed if nobody reattaches within
  10 minutes. A different command under the same job id is refused. If a detached job produces more than
  16 MiB of output per stream before a client returns, `run` fails to resume with `output expired`, and
  `attach` continues from the oldest retained byte and says how much was lost.
- **Stdin.** `--stdin` / `"stdin":true` stream input with flow control. A command with stdin is not
  durable: if the connection drops it is killed, because stdin cannot be replayed.
- **Cancellation and timeouts.** Cancel and timeout kill the whole process tree (process group on Unix,
  `taskkill /T` on Windows).
- **Not provided:** pseudo-terminals (interactive shells, programs that require a TTY), directory
  transfer (use `tar` through `run --stdin`), and resumable uploads.

## Protocol

Frames are `type(1) stream(4) length(4) payload`; control payloads are JSON, data payloads are raw. Client
to server: `open`, `stdin`, `stdin-eof`, `cancel`, `credit`, `detach`. Server to client: `out`, `err`,
`exit`, `error`, `meta`, `credit`. Stream ids increase monotonically per connection. See `cmd/eco/frame.go`.

## Verification

`go test ./...` covers pairing and man-in-the-middle detection, concurrency on one connection, 40 MiB
output with a slow consumer, a stalled stream not blocking others, cancellation, timeout, stdin, reconnect
without duplicates or reruns, idempotent job ids, commands that leave background children holding their
output, `--wait` / `start` / `attach` without lost or duplicated output, jobs surviving a killed client,
`jobs` / `kill`, byte-exact `write` / `cat`, port forwarding (3 MB and concurrent connections), file
transfer with resume and corruption detection, and the JSON session. The tests run on Windows and were also
exercised end to end with the compiled binaries on Windows. `go test -race` has not been run (it needs a C
compiler).
