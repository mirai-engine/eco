#!/usr/bin/env python3
"""Loopback integration tests for the Noise/UDP executable."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

BINARY = Path(__file__).resolve().parent.parent / "bin" / "eco-odin"


def cli(*args, env=None, data=None, timeout=12, check=True):
    result = subprocess.run(
        [BINARY, *args], env=env, input=data, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if check and result.returncode:
        raise AssertionError(f"{args!r} exited {result.returncode}: {result.stderr!r}")
    return result


def read_exact(socket_, size):
    result = bytearray()
    while len(result) < size:
        part = socket_.recv(size - len(result))
        if not part:
            raise EOFError("local daemon closed the request")
        result += part
    return bytes(result)


def send_message(socket_, opcode, body=b""):
    payload = bytes([opcode]) + body
    socket_.sendall(len(payload).to_bytes(2, "little") + payload)


def read_message(socket_):
    header = read_exact(socket_, 2)
    return read_exact(socket_, int.from_bytes(header, "little"))


@contextmanager
def background(*args, env=None):
    process = subprocess.Popen(
        [BINARY, *args], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)


def main():
    # POSIX bounds the length of an AF_UNIX address.
    with tempfile.TemporaryDirectory(prefix="eco-", dir="/tmp") as tmp:
        base = Path(tmp)
        root, keys = base / "repo", base / "keys"
        root.mkdir()
        keys.mkdir()
        server_secret, client_secret = keys / "server", keys / "client"
        server_key = cli("keygen", server_secret).stdout.decode().strip()
        client_key = cli("keygen", client_secret).stdout.decode().strip()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        address = f"127.0.0.1:{port}"
        local_socket = base / "s"
        env = {**os.environ, "ECO_ODIN_SOCKET": str(local_socket)}

        with background("serve", address, server_secret, client_key, root, "run") as server:
            assert server.stderr.readline().startswith(b"eco-odin listening")
            assert cli("ping-early", address, client_secret, server_key).stdout.startswith(b"pong")
            with background("client", local_socket, address, client_secret, server_key) as client:
                deadline = time.monotonic() + 4
                while not local_socket.exists() and time.monotonic() < deadline and client.poll() is None:
                    time.sleep(0.01)
                assert local_socket.exists(), client.poll()
                assert cli("ping", env=env).stdout == b"pong\n"
                assert cli("list", ".", env=env).stdout == b""

                content = os.urandom(256 * 1024)
                source, result = base / "source", base / "download"
                source.write_bytes(content)
                cli("put", source, "fixture", env=env)
                assert (root / "fixture").read_bytes() == content
                assert cli("read", "fixture", env=env).stdout == content
                cli("get", "fixture", result, env=env)
                assert result.read_bytes() == content
                assert cli("stat", "fixture", env=env).stdout.startswith(b"file\t262144\t")
                assert cli("list", ".", env=env).stdout == b'"fixture"\n'
                assert len(cli("hash", "fixture", env=env).stdout.strip()) == 64
                assert cli("hash", ".", env=env, check=False).returncode != 0
                (root / "outside").symlink_to(keys)
                for path in ["../keys/server", "outside/server", "/etc/passwd"]:
                    assert cli("read", path, env=env, check=False).returncode != 0

                # The daemon should service a second stream while a process is still running.
                with ThreadPoolExecutor() as pool:
                    slow = pool.submit(
                        cli, "run", "--", "/bin/sh", "-c", "sleep 1; printf late", env=env,
                    )
                    time.sleep(0.12)
                    assert cli("ping", env=env).stdout == b"pong\n"
                    assert not slow.done()
                    assert slow.result().stdout == b"late"
                # Exercise descriptor registration with more child pipes than the small poll path.
                with ThreadPoolExecutor(max_workers=8) as pool:
                    calls = [
                        pool.submit(cli, "run", "--", "/bin/sh", "-c", "sleep 0.2; printf concurrent", env=env)
                        for _ in range(8)
                    ]
                    assert cli("ping", env=env).stdout == b"pong\n"
                    assert all(result.result().stdout == b"concurrent" for result in calls)


                run = cli("run", "--cwd", ".", "--", "/bin/sh", "-c",
                          "printf out; printf err >&2; exit 7", env=env, check=False)
                assert (run.returncode, run.stdout, run.stderr) == (7, b"out", b"err")
                run = cli("run", "--timeout-ms", "70", "--", "/bin/sleep", "6", env=env, check=False)
                assert run.returncode != 0 and b"timed out" in run.stderr
                assert cli("run", "--", "/usr/bin/true", env=env).returncode == 0

                with socket.socket(socket.AF_UNIX) as local:
                    local.settimeout(4)
                    local.connect(str(local_socket))
                    send_message(local, 5, b"fixture")
                    assert read_message(local) == bytes([39])  # Ready
                    send_message(local, 16, b"corrupted content")
                    send_message(local, 17, bytes(32))
                    failure = read_message(local)
                    assert failure[0] == 38 and b"BLAKE3" in failure
                assert (root / "fixture").read_bytes() == content
                assert not list(root.glob(".eco-part-*"))
    print("ECO Odin loopback integration passed")


if __name__ == "__main__":
    main()
