# eco

Experimental remote command transport for agents. One TLS 1.3 connection carries newline-delimited
JSON requests and events. Both peers authenticate using certificates issued by a dedicated CA.
An authenticated client can execute arbitrary programs with the server user's privileges. The server
is not a sandbox; bind to a private address and restrict access at the firewall.

## Build

```sh
go build -o eco ./cmd/eco
GOOS=windows GOARCH=amd64 go build -o eco.exe ./cmd/eco
```

Generate a dedicated CA and separate server and client credentials on the Mac:

```sh
eco setup eco-credentials
```

The directory must not already exist. The command creates `client` and `server` directories. Copy the
`server` directory to Windows using a secure channel such as a USB drive; keep the `client` directory
on the Mac. Do not upload either directory or their private keys. The CA signing key is discarded.
The generated certificates expire after one year and the server identity is `eco.local`.

On the server:

```sh
eco serve --addr 127.0.0.1:8443 --ca server/ca.pem --cert server/cert.pem --key server/key.pem
```

Replace the loopback address with the server's private LAN address for a remote connection. On the
client:

```sh
eco connect --addr SERVER_IP:8443 --server-name eco.local --ca client/ca.pem --cert client/cert.pem --key client/key.pem
```

The client reads one JSON request per line from stdin and writes one JSON event per line to stdout;
diagnostics go to stderr. Keep stdin open to reuse the TLS connection.

```json
{"id":"health-1","method":"ping"}
{"id":"build-1","method":"exec","executable":"git","args":["status","--short"],"cwd":"C:\\work\\project","timeout_ms":60000}
```

Ping yields `pong`. Exec yields `started`, zero or more `stdout` / `stderr` events, then `exit` with
`exit_code`. Output `data` is base64-encoded bytes, preserving arbitrary binary output. Invalid requests
or failures to start a process yield an `error` event. A timeout or output truncation is indicated in
the exit event's `error` field. The default timeout is 60 seconds and the maximum is one hour; output
is capped at 8 MiB per command, across both streams. Requests execute serially on each connection.

IDs must be unique within a connection. They are not persisted across connections. If a connection
fails after a request was sent, execution may have occurred; do not automatically retry a command with
side effects. A timeout terminates the direct child; descendants may continue. The current protocol has
no cancellation, interactive stdin, file transfer, or durable job recovery. Do not rely on it for
unattended work that needs those features.

## Verification

`go test -race ./...` exercises TLS and request handling on the local platform. Windows compilation
alone does not establish that the server runs or that process behavior works on Windows. No latency
comparison has been performed.
