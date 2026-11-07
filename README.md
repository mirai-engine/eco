# eco

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
answer `y` on the server. The server stores the client fingerprint in `authorized_clients`; the client
stores the server fingerprint in `known_servers`. From then on no approval is needed.

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

```sh
eco run  --addr ADDR [--cwd DIR] [--timeout 30s] [--env K=V] [--stdin] -- program args...
eco put  --addr ADDR LOCAL REMOTE
eco get  --addr ADDR REMOTE LOCAL
eco ping --addr ADDR
eco connect --addr ADDR        # JSON lines for programs, see below
```

- `run` streams stdout and stderr to the local ones and exits with the remote exit code. Ctrl-C kills the
  remote process tree. Without `--stdin` the command is durable: if the connection drops, `run` reconnects
  and continues where it left off.
- `put` writes to `REMOTE.eco-part` and renames after verifying size and SHA-256, so the destination is never
  half written. `get` verifies the SHA-256 of the whole file and resumes from `LOCAL.eco-part` if a previous
  download was interrupted; a partial that fails verification is discarded.

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
  ambiguous failure is safe. Finished jobs stay available for 10 minutes; a running job nobody reattaches
  to within 10 minutes is killed; a different command under the same job id is refused. If a detached job
  produces more than 16 MiB of output per stream before the client returns, resuming fails with
  `output expired`.
- **Stdin.** `--stdin` / `"stdin":true` stream input with flow control. A command with stdin is not
  durable: if the connection drops it is killed, because stdin cannot be replayed.
- **Cancellation and timeouts.** Cancel and timeout kill the whole process tree (process group on Unix,
  `taskkill /T` on Windows).
- **Not provided:** pseudo-terminals (interactive shells, programs that require a TTY), directory
  transfer (use `tar` through `run --stdin`), and resumable uploads.

## Protocol

Frames are `type(1) stream(4) length(4) payload`; control payloads are JSON, data payloads are raw. Client
to server: `open`, `stdin`, `stdin-eof`, `cancel`, `credit`. Server to client: `out`, `err`, `exit`,
`error`, `meta`, `credit`. Stream ids increase monotonically per connection. See `cmd/eco/frame.go`.

## Verification

`go test ./...` covers pairing and man-in-the-middle detection, concurrency on one connection, 40 MiB
output with a slow consumer, a stalled stream not blocking others, cancellation, timeout, stdin, reconnect
without duplicates or reruns, idempotent job ids, file transfer with resume and corruption detection, and
the JSON session. The tests run on Windows and were also exercised end to end with the compiled binaries on
Windows. `go test -race` has not been run (it needs a C compiler).
