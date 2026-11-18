#!/usr/bin/env python3
"""Measure warm operations, cold ping, transfer rate and idle RSS on loopback."""
from argparse import ArgumentParser
import os
from pathlib import Path
import socket
import statistics
import struct
import subprocess
import tempfile
import time

from extended_test import endpoint, port_for, wait_ready
from smoke import background, cli, read_message, send_message


def measure(label, count, call):
    samples = []
    for _ in range(count):
        start = time.perf_counter_ns()
        call()
        samples.append((time.perf_counter_ns() - start) / 1000)
    samples.sort()
    p95 = samples[(len(samples) * 95 + 99) // 100 - 1]
    print(f"{label:28s} p50 {statistics.median(samples):9.1f} µs  p95 {p95:9.1f} µs  n={count}", flush=True)


def warm_request(path, operation, payload=b""):
    with socket.socket(socket.AF_UNIX) as local:
        local.settimeout(5)
        local.connect(str(path))
        send_message(local, operation, payload)
        while (message := read_message(local))[0] != 37:
            assert message[0] != 38, message
        assert message == b"\x25\x00\x00\x00\x00", message


def rss(*processes):
    pids = ",".join(str(process.pid) for process in processes)
    output = subprocess.check_output(["ps", "-o", "pid=,rss=", "-p", pids], text=True)
    return {int(pid): int(kib) / 1024 for pid, kib in (line.split() for line in output.splitlines())}


def main():
    args = ArgumentParser(description=__doc__)
    args.add_argument("--bulk-mib", type=int, default=8)
    args.add_argument("--footprint", action="store_true", help="report the macOS vmmap physical footprint")
    args = args.parse_args()
    with tempfile.TemporaryDirectory(prefix="eco-", dir="/tmp") as directory:
        base = Path(directory)
        server_secret, client_secret = base / "server", base / "client"
        server_key = cli("keygen", server_secret).stdout.decode().strip()
        client_key = cli("keygen", client_secret).stdout.decode().strip()
        target = endpoint(port_for())
        path = base / "s"
        env = {**os.environ, "ECO_ODIN_SOCKET": str(path)}
        with background("serve", target, server_secret, client_key, base, "run") as server:
            assert b"listening" in server.stderr.readline()
            time.sleep(0.2)
            print(f"server idle, no client       RSS {rss(server)[server.pid]:.2f} MiB", flush=True)

            def cold_ping():
                assert cli("ping-early", target, client_secret, server_key).stdout.startswith(b"pong")

            measure("cold ping, new CLI + Noise", 40, cold_ping)
            with background("client", path, target, client_secret, server_key) as client:
                wait_ready(path, client)
                warm_request(path, 1)
                time.sleep(0.2)
                resident = rss(server, client)
                print(f"warm idle RSS                server {resident[server.pid]:.2f} MiB  client {resident[client.pid]:.2f} MiB", flush=True)
                if args.footprint:
                    for role, process in (("server", server), ("client", client)):
                        output = subprocess.check_output(["vmmap", "-summary", str(process.pid)], text=True)
                        label = next(line for line in output.splitlines() if line.startswith("Physical footprint:"))
                        print(f"{role} {label}", flush=True)

                measure("warm ping through UDS", 500, lambda: warm_request(path, 1))
                measure("warm stat through UDS", 300, lambda: warm_request(path, 2, b"server"))
                run = struct.pack("<IBHH", 10000, 0, 0, 0) + b".\0/usr/bin/true\0"
                measure("warm /usr/bin/true", 100, lambda: warm_request(path, 8, run))
                measure("warm ping + new CLI", 100, lambda: cli("ping", env=env))

                source, result = base / "source", base / "download"
                with source.open("wb") as fixture:
                    for _ in range(args.bulk_mib):
                        fixture.write(os.urandom(1024 * 1024))
                for direction, request in (
                    ("put", ("put", source, "remote")),
                    ("get", ("get", "remote", result)),
                ):
                    begin = time.perf_counter()
                    cli(*request, env=env, timeout=60)
                    seconds = time.perf_counter() - begin
                    print(f"{direction:28s} {args.bulk_mib / seconds:7.1f} MiB/s  ({args.bulk_mib} MiB)", flush=True)
                assert source.read_bytes() == result.read_bytes()
                resident = rss(server, client)
                print(f"RSS after bulk              server {resident[server.pid]:.2f} MiB  client {resident[client.pid]:.2f} MiB")


if __name__ == "__main__":
    main()
