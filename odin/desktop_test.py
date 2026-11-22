#!/usr/bin/env python3
"""Loopback desktop IPC and playback under deterministic UDP loss and reordering."""
from contextlib import ExitStack
import os
from pathlib import Path
from queue import Queue
import select
import socket
from socketserver import StreamRequestHandler, ThreadingUnixStreamServer
import struct
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time

from extended_test import endpoint, port_for, wait_ready
from smoke import BINARY, background, cli, read_exact

FRAME_KIND = 13
CHUNK_BYTES = 1200 - 24 - 16 - 12
CHUNKS_PER_FRAME = 4


def fixture(number):
    # JPEG markers surround a deterministic payload for byte-exact transport assertions.
    return b"\xff\xd8" + bytes([number % 128]) * (3 * CHUNK_BYTES + 23) + b"\xff\xd9"


class DesktopHelper(StreamRequestHandler):
    def handle(self):
        try:
            while True:
                size, = struct.unpack("<I", read_exact(self.request, 4))
                body = read_exact(self.request, size)
                self.server.requests.put(body)
                if body == b"\x01":
                    self.server.frames += 1
                    response = b"\0" + fixture(self.server.frames)
                else:
                    response = b"\0"
                self.request.sendall(struct.pack("<I", len(response)) + response)
        except (EOFError, BrokenPipeError, ConnectionResetError):
            pass


def relay(sock, server_port, stop, observed_sizes):
    target = ("127.0.0.1", server_port)
    client = None
    count = 0
    delayed = []
    sock.settimeout(0.05)
    while not stop.is_set():
        try:
            body, source = sock.recvfrom(4096)
        except socket.timeout:
            continue
        if source != target:
            client = source
            sock.sendto(body, target)
            continue
        if client is None:
            continue
        if body[4:5] == bytes([FRAME_KIND]):
            observed_sizes.put(len(body))
            count += 1
            if count in (2, CHUNKS_PER_FRAME + 1):
                delayed.append(body)
                continue
            if count == CHUNKS_PER_FRAME + 2:
                # The second chunk of frame 2 arrives first. The late chunk of frame 1
                # would complete frame 1 if the receiver still held its data.
                sock.sendto(body, client)
                sock.sendto(delayed[0], client)
                sock.sendto(delayed[1], client)
                sock.sendto(body, client)
                delayed.clear()
                continue
        sock.sendto(body, client)


def read_images(pipe, count):
    results = []
    pending = bytearray()
    deadline = time.monotonic() + 8
    while len(results) < count:
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([pipe], [], [], remaining)[0], "timed out reading JPEGs"
        body = os.read(pipe.fileno(), 8192)
        assert body, "desktop stream closed before reaching the requested number of images"
        pending.extend(body)
        while (end := pending.find(b"\xff\xd9")) >= 0:
            results.append(bytes(pending[:end + 2]))
            del pending[:end + 2]
    return results[:count]


def main():
    with TemporaryDirectory(prefix="eco-ui-", dir="/tmp") as directory, ExitStack() as stack:
        base = Path(directory)
        helper = stack.enter_context(ThreadingUnixStreamServer(str(base / "helper"), DesktopHelper))
        helper.requests = Queue()
        helper.frames = 0
        helper_thread = Thread(target=helper.serve_forever)
        helper_thread.start()
        stack.callback(helper_thread.join)
        stack.callback(helper.shutdown)

        server_key = cli("keygen", base / "server.key").stdout.decode().strip()
        client_key = cli("keygen", base / "client.key").stdout.decode().strip()
        cli("trust", "add", base / "clients", client_key, "desktop")
        port = port_for()
        sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        sock.bind(("127.0.0.1", 0))
        stop, sizes = Event(), Queue()
        proxy = Thread(target=relay, args=(sock, port, stop, sizes))
        proxy.start()
        stack.callback(proxy.join)
        stack.callback(stop.set)
        address = endpoint(sock.getsockname()[1])
        local = base / "client"
        env = {**os.environ, "ECO_SOCKET": str(local), "ECO_DESKTOP_SOCKET": helper.server_address}
        server = stack.enter_context(background("serve", endpoint(port), base / "server.key",
                                                base / "clients", base, "run", env=env))
        assert b"listening" in server.stderr.readline()
        bridge = stack.enter_context(background("client", local, address, base / "client.key", server_key, env=env))
        wait_ready(local, bridge)

        assert cli("desktop", "capture", env=env).stdout == fixture(1)
        assert helper.requests.get(timeout=2) == b"\x01"
        cli("desktop", "click", "111", "222", "right", env=env)
        assert helper.requests.get(timeout=2) == struct.pack("<BHHB", 2, 111, 222, 1)
        cli("desktop", "type", "Argentina 🎮", env=env)
        assert helper.requests.get(timeout=2) == b"\x04" + "Argentina 🎮".encode()

        command = [BINARY, "desktop", "stream", "6"]
        with subprocess.Popen(command, env=env, stdout=subprocess.PIPE) as video:
            try:
                first, second = read_images(video.stdout, 2)
                assert (first, second) == (fixture(3), fixture(4))
                cli("desktop", "key", "36", env=env)
                rejected = cli("desktop", "stream", env=env, check=False)
                assert rejected.returncode == 125 and b"already streaming" in rejected.stderr
                cli("ping", env=env)
                assert all(0 < length <= 1200 for length in list(sizes.queue))
                assert 1200 in list(sizes.queue)
            finally:
                video.terminate()
                video.wait(timeout=5)

        with subprocess.Popen(command, env=env, stdout=subprocess.PIPE) as video:
            try:
                assert read_images(video.stdout, 1)
            finally:
                video.terminate()
                video.wait(timeout=5)

        readonly_port = port_for()
        readonly = stack.enter_context(background("serve", endpoint(readonly_port), base / "server.key",
                                                  base / "clients", base, "read", env=env))
        assert b"listening" in readonly.stderr.readline()
        readonly_socket = base / "readonly"
        readonly_env = {**env, "ECO_SOCKET": str(readonly_socket)}
        readonly_client = stack.enter_context(background("client", readonly_socket, endpoint(readonly_port),
                                                         base / "client.key", server_key, env=readonly_env))
        wait_ready(readonly_socket, readonly_client)
        denied = cli("desktop", "capture", env=readonly_env, check=False)
        assert denied.returncode == 125 and b"unconfined execution" in denied.stderr

    print("Desktop capture, input, MTU, loss recovery, cancellation, and access checks passed")


if __name__ == "__main__":
    main()
