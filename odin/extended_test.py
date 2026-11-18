#!/usr/bin/env python3
"""Integration coverage for permissions, migration, tunnels and durable jobs."""
from contextlib import ExitStack
import fcntl
import os
from pathlib import Path
import pty
import selectors
import socket
import struct
import subprocess
import tempfile
import termios
import threading
import time

from smoke import BINARY, background, cli, read_exact


def endpoint(port):
    return f"127.0.0.1:{port}"


def port_for(type_=socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, type_) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_ready(path, process):
    deadline = time.monotonic() + 4
    while not path.exists() and time.monotonic() < deadline and process.poll() is None:
        time.sleep(0.01)
    assert path.exists(), process.poll()


def set_size(terminal, rows, cols):
    fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def test_terminal(env):
    assert cli("run", "--stdin", "--", "/bin/cat", data=b"raw\0bytes\n", env=env).stdout == b"raw\0bytes\n"
    larger = os.urandom(2*1024*1024)
    echo = cli("run", "--stdin", "--", "/bin/cat", data=larger, env=env)
    assert echo.stdout == larger

    with subprocess.Popen([BINARY, "watch", "watch.txt"], env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as watch:
        try:
            first = watch.stdout.readline()
            assert first.startswith(b"file\t1\t"), first
            Path(env["TEST_ROOT"], "watch.txt").write_bytes(b"updated")
            assert watch.stdout.readline().startswith(b"file\t7\t")
        finally:
            watch.terminate()
            watch.wait(timeout=3)

    master, slave = pty.openpty()
    try:
        set_size(slave, 27, 93)
        command = [BINARY, "tty", "--", "/bin/sh", "-c", "stty size; read line; stty size; printf 'seen:%s' \"$line\""]
        with subprocess.Popen(command, env=env, stdin=slave, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as terminal:
            try:
                assert terminal.stdout.readline() == b"27 93\r\n"
                set_size(slave, 49, 107)
                time.sleep(0.15)
                os.write(master, b"resized\n")
                out, err = terminal.communicate(timeout=4)
                assert terminal.returncode == 0 and b"49 107\r\n" in out and b"seen:resized" in out, (out, err)
            finally:
                if terminal.poll() is None:
                    terminal.terminate()
                    terminal.wait(timeout=3)
    finally:
        os.close(master)
        os.close(slave)
    print("PTY, resize, stdin, and watch passed", flush=True)


def test_tunnels(env):
    with socket.socket() as target:
        target.bind(("127.0.0.1", 0))
        target.listen()
        target.settimeout(5)

        def tcp_reply():
            conn, _ = target.accept()
            with conn:
                conn.settimeout(5)
                data = bytearray()
                while block := conn.recv(65536):
                    data += block
                conn.sendall(bytes(data[::-1]))

        worker = threading.Thread(target=tcp_reply, daemon=True)
        worker.start()
        local_port = port_for(socket.SOCK_STREAM)
        with background("forward", endpoint(local_port), endpoint(target.getsockname()[1]), env=env) as tunnel:
            assert b"forwarding" in tunnel.stderr.readline()
            with socket.create_connection(("127.0.0.1", local_port), timeout=5) as local:
                payload = os.urandom(30_000)
                local.sendall(payload)
                local.shutdown(socket.SHUT_WR)
                assert read_exact(local, len(payload)) == payload[::-1]
                assert local.recv(1) == b""
        worker.join(5)
        assert not worker.is_alive()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
        target.bind(("127.0.0.1", 0))
        target.settimeout(5)

        def udp_reply():
            data, sender = target.recvfrom(4096)
            target.sendto(data[::-1], sender)

        worker = threading.Thread(target=udp_reply, daemon=True)
        worker.start()
        local_port = port_for()
        with background("forward-udp", endpoint(local_port), endpoint(target.getsockname()[1]), env=env) as tunnel:
            assert b"forwarding" in tunnel.stderr.readline()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as local:
                local.settimeout(5)
                local.sendto(b"udp query", ("127.0.0.1", local_port))
                assert local.recv(4096) == b"yreuq pdu"
        worker.join(5)
        assert not worker.is_alive()
    print("TCP half-close and UDP tunnel passed", flush=True)


class Fault_Proxy:
    def __init__(self, port):
        self.target = ("127.0.0.1", port)
        self.front, self.back = self.make_socket(), self.make_socket()
        self.port = self.front.getsockname()[1]
        self.stop = threading.Event()
        self.rebind = threading.Event()
        self.changed = threading.Event()
        self.client = None
        self.count = 0
        self.rebind_after = None
        self.dropped = self.duplicated = self.reordered = self.tampered = 0
        self.thread = threading.Thread(target=self.run, daemon=True)

    @staticmethod
    def make_socket():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        return sock

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(2)
        self.front.close()
        self.back.close()

    def run(self):
        deferred = None
        with selectors.DefaultSelector() as poll:
            poll.register(self.front, selectors.EVENT_READ)
            poll.register(self.back, selectors.EVENT_READ)
            while not self.stop.is_set():
                if self.rebind.is_set() or (self.rebind_after is not None and self.count >= self.rebind_after):
                    self.rebind_after = None
                    poll.unregister(self.back)
                    old = self.back
                    self.back = self.make_socket()
                    old.close()
                    poll.register(self.back, selectors.EVENT_READ)
                    deferred = None
                    self.rebind.clear()
                    self.changed.set()
                for key, _ in poll.select(0.003):
                    source = key.fileobj
                    packet, sender = source.recvfrom(1300)
                    if source is self.front:
                        self.client = sender
                        out, address = self.back, self.target
                    elif self.client:
                        out, address = self.front, self.client
                    else:
                        continue
                    if packet[4:5] == b"\x03":
                        self.count += 1
                        if self.count % 29 == 0:
                            self.dropped += 1
                            continue
                        if self.count % 37 == 0 and deferred is None:
                            deferred = out, address, packet, time.monotonic() + 0.004
                            self.reordered += 1
                            continue
                        if self.count % 47 == 0:
                            out.sendto(packet[:-1] + bytes([packet[-1] ^ 1]), address)
                            self.tampered += 1
                        if self.count % 59 == 0:
                            out.sendto(packet, address)
                            self.duplicated += 1
                    out.sendto(packet, address)
                if deferred and time.monotonic() >= deferred[3]:
                    out, address, packet, _ = deferred
                    out.sendto(packet, address)
                    deferred = None


def test_faults(base, server_port, client_secret, server_key, env):
    local = base / "faults"
    env = {**env, "ECO_ODIN_SOCKET": str(local)}
    original, cloned = base / "fault-source", base / "fault-result"
    payload = os.urandom(512 * 1024)
    original.write_bytes(payload)
    with Fault_Proxy(server_port) as proxy:
        with background("client", local, endpoint(proxy.port), client_secret, server_key, env=env) as client:
            wait_ready(local, client)
            cli("ping", env=env)
            proxy.rebind.set()
            assert proxy.changed.wait(2)
            cli("put", original, "migration-test", env=env, timeout=16)
            proxy.changed.clear()
            proxy.rebind_after = proxy.count + 40
            cli("get", "migration-test", cloned, env=env, timeout=16)
            assert proxy.changed.is_set()
            assert cloned.read_bytes() == payload
            assert proxy.dropped and proxy.duplicated and proxy.reordered and proxy.tampered
            command = "printf once >> side-effects"
            cli("run", "--", "/bin/sh", "-c", command, env=env, timeout=16)
            assert cli("read", "side-effects", env=env).stdout == b"once"
    print("UDP loss, duplicates, reorder, tampering and source-port migration passed", flush=True)


def test_capabilities(base, root, server_secret, server_key, client_secret, client_key, env):
    port = port_for()
    key_path = base / "issuer"
    issuer = cli("issuer-keygen", key_path).stdout.decode().strip()
    (root / "scope").mkdir()
    (root / "scope" / "inside").write_bytes(b"allowed")
    (root / "scope" / "link").symlink_to(root / "outside")
    (root / "outside").write_bytes(b"disallowed")
    capability = cli("grant", key_path, server_key, client_key, "r", "60", "scope").stdout.decode().strip()
    assert cli("grant", key_path, server_key, client_key, "x", "60", "scope", check=False).returncode
    with background("serve", endpoint(port), server_secret, client_key, root, "run", issuer) as server:
        assert b"listening" in server.stderr.readline()
        wrong = capability[:-1] + ("a" if capability[-1] != "a" else "b")
        assert cli("ping-early", endpoint(port), client_secret, server_key,
                   env={**env, "ECO_ODIN_CAPABILITY": wrong}, check=False).returncode
        local = base / "cap"
        env = {**env, "ECO_ODIN_CAPABILITY": capability, "ECO_ODIN_SOCKET": str(local)}
        with background("client", local, endpoint(port), client_secret, server_key, env=env) as client:
            wait_ready(local, client)
            assert cli("read", "inside", env=env).stdout == b"allowed"
            for path in ("../outside", "outside", "link"):
                assert cli("read", path, env=env, check=False).returncode
            assert cli("write", "inside", env=env, data=b"denied", check=False).returncode
            assert cli("run", "--", "/usr/bin/true", env=env, check=False).returncode
    print("signed scoped grant, wrong signature and symlink escape denial passed", flush=True)


def test_jobs(stack, base, root, port, server_secret, client_secret, server_key, client_key, env):
    argv = ("--", "/bin/sh", "-c", "printf one; sleep 2; printf two; printf err >&2; exit 7")
    job = cli("start", *argv, env=env).stdout.decode().strip()
    assert len(job) == 32 and cli("start", "--id", job, *argv, env=env).stdout.decode().strip() == job
    assert cli("start", "--id", job, "--", "/bin/echo", "different", env=env, check=False).returncode
    assert job in cli("jobs", env=env).stdout.decode()
    stack.close()  # stop both daemons while the worker is still running
    with ExitStack() as new_stack:
        server = new_stack.enter_context(background("serve", endpoint(port), server_secret, client_key, root, "run", env=env))
        assert b"listening" in server.stderr.readline()
        new_client = base / "second"
        client = new_stack.enter_context(background("client", new_client, endpoint(port), client_secret, server_key))
        wait_ready(new_client, client)
        env = {**env, "ECO_ODIN_SOCKET": str(new_client)}
        result = cli("attach", job, "3", "0", env=env, check=False)
        assert (result.returncode, result.stdout, result.stderr) == (7, b"two", b"err"), result
        running = cli("start", "--", "/bin/sleep", "20", env=env).stdout.decode().strip()
        cli("kill", running, env=env)
        assert cli("attach", running, env=env, check=False).returncode == 130
    print("detached job survived daemon restart, offsets and cancel passed", flush=True)


def main():
    with tempfile.TemporaryDirectory(prefix="eco-", dir="/tmp") as directory:
        base = Path(directory)
        root, jobs = base / "root", base / "jobs"
        root.mkdir()
        jobs.mkdir(mode=0o700)
        (root / "watch.txt").write_bytes(b"x")
        server_secret, client_secret = base / "server", base / "client"
        server_key = cli("keygen", server_secret).stdout.decode().strip()
        client_key = cli("keygen", client_secret).stdout.decode().strip()
        port, local = port_for(), base / "s"
        env = {**os.environ, "ECO_ODIN_SOCKET": str(local), "ECO_ODIN_JOBS": str(jobs), "TEST_ROOT": str(root)}
        with ExitStack() as stack:
            server = stack.enter_context(background("serve", endpoint(port), server_secret, client_key, root, "run", env=env))
            assert b"listening" in server.stderr.readline()
            client = stack.enter_context(background("client", local, endpoint(port), client_secret, server_key))
            wait_ready(local, client)
            test_terminal(env)
            test_tunnels(env)
            test_faults(base, port, client_secret, server_key, env)
            test_capabilities(base, root, server_secret, server_key, client_secret, client_key, env)
            test_jobs(stack, base, root, port, server_secret, client_secret, server_key, client_key, env)


if __name__ == "__main__":
    main()
