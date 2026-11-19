# ECO

ECO lets you and your agents work on a remote machine from a local CLI. The Odin client keeps one
authenticated session open for commands, terminals, native file operations, and TCP or UDP forwarding.
Detached jobs can be reattached after a connection drops.

ECO uses a binary protocol over UDP with Noise authentication and encryption. Builds are documented
for macOS arm64, Linux arm64, and Windows x64.

## Get started

On macOS or Linux, run `./odin/build.sh` to build `bin/eco-odin`. On Windows, use the
[Windows build instructions](odin/README.md#build-and-run-on-windows).

Follow the [pairing instructions](odin/README.md#build-and-pair) to authorize a client. Choose `run`
when starting the server if the client should be able to run tools on that machine. Remote processes
run with the server account's privileges unless a scoped execution grant applies.

## Use ECO from an agent

After pairing and setting the client environment, an agent with a local shell tool can call the CLI
directly. This example uses a client built on macOS or Linux and a remote checkout with Git installed.

```sh
./bin/eco-odin ping
./bin/eco-odin run -- git status --short
./bin/eco-odin read README.md
```

With a [job store](odin/README.md#build-and-pair) configured on the server, use `start` and `attach`
for long-running commands. See the [Odin guide](odin/README.md) for CLI options, access modes, and
[adapters for third-party agents and tools](odin/README.md#adapters-for-agents-and-tools).

For screenshots, input, or live JPEG preview, see [desktop control](odin/README.md#desktop-control).
