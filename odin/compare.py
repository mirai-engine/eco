#!/usr/bin/env python3
"""Interleave ECO and OpenSSH loopback benchmarks with temporary credentials."""
from argparse import ArgumentParser
from collections import defaultdict
from contextlib import ExitStack
import getpass
import hashlib
import json
import os
from pathlib import Path
import random
import shlex
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time

from extended_test import endpoint, port_for, wait_ready
from smoke import BINARY, background, cli, read_message, send_message


def sample(times, case, callback):
    start = time.perf_counter_ns()
    callback()
    times[case].append((time.perf_counter_ns() - start) / 1e6)


def summarize(times, size=None):
    for case, values in times.items():
        med = statistics.median(values)
        p95 = sorted(values)[(95*len(values)+99)//100 - 1]
        rate = f", {size*1000/med:.1f} MiB/s" if size else ""
        print(f"{case:30s} {med:9.3f} ms p50  {p95:9.3f} ms p95{rate}  n={len(values)}", flush=True)


def cli_call(args, directory=None, env=None):
    result = subprocess.run(args, cwd=directory, env=env, capture_output=True, timeout=25, check=False)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr!r}")
    return result.stdout


def start(stack, args, **options):
    process = stack.enter_context(subprocess.Popen(args, **options))

    def stop():
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    stack.callback(stop)
    return process


def ssh_session(stack, base, control):
    port = port_for(socket.SOCK_STREAM)
    for key in ("host", "client"):
        cli_call(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", base/key])
    (base/"known").write_text(f"[127.0.0.1]:{port} " + (base/"host.pub").read_text())
    (base/"config").write_text(f"""ListenAddress 127.0.0.1
Port {port}
HostKey {base / 'host'}
PidFile {base / 'sshd.pid'}
AuthorizedKeysFile {base / 'client.pub'}
AllowUsers {getpass.getuser()}
StrictModes yes
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitUserRC no
PrintMotd no
Subsystem sftp internal-sftp
""")
    log = stack.enter_context((base/"sshd.log").open("wb"))
    server = start(stack, ["/usr/sbin/sshd", "-D", "-e", "-f", base/"config"], stderr=log)
    for _ in range(100):
        if server.poll() is not None:
            raise RuntimeError((base/"sshd.log").read_text())
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                break
        time.sleep(0.02)
    options = ["-F", "/dev/null", "-i", str(base/"client"), "-o", "IdentitiesOnly=yes",
               "-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", f"UserKnownHostsFile={base/'known'}", "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "Compression=no", "-o", f"ControlPath={control}"]
    ssh = ["ssh", *options, "-p", str(port), "-T"]
    master = start(stack, [*ssh, "-MN", "127.0.0.1"])
    wait_ready(control, master)
    script = "import json,subprocess,sys\nfor line in sys.stdin:\n r=json.loads(line); o=subprocess.run(r, capture_output=True); print(json.dumps([o.returncode,o.stdout.decode()]),flush=True)"
    worker = start(stack, [*ssh, "127.0.0.1", shlex.join(["python3", "-u", "-c", script])],
                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    return server, master, worker, ssh, options, port


def rss_group(*processes, descend=False):
    entries = defaultdict(list)
    for row in subprocess.check_output(["ps", "-Ao", "pid=,ppid=,rss="], text=True).splitlines():
        pid, owner, resident = map(int, row.split())
        entries[owner].append((pid, resident))
        entries[None].append((pid, resident))
    memory = dict(entries[None])
    chosen = [process.pid for process in processes]
    if descend:
        for pid in chosen:
            chosen.extend(item[0] for item in entries[pid])
    return sum(memory.get(pid, 0) for pid in set(chosen))/1024


def local_request(conn, opcode, payload=b""):
    send_message(conn, opcode, payload)
    result = []
    for _ in range(16):
        frame = read_message(conn)
        if frame[0] == 37:
            assert frame == b"\x25\0\0\0\0"
            return result
        if frame[0] == 38:
            raise RuntimeError(frame[1:].decode())
        result.append(frame)
    raise RuntimeError("unexpected response stream")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=40)
    parser.add_argument("--size-mib", type=int, default=32)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="eco-", dir="/tmp") as tmp, ExitStack() as stack:
        base = Path(tmp)
        server_key = cli("keygen", base/"eco-server").stdout.decode().strip()
        client_key = cli("keygen", base/"eco-client").stdout.decode().strip()
        cli("trust", "add", base/"eco-clients", client_key, "compare")
        local = base/"eco.sock"
        target = endpoint(port_for())
        env = {**os.environ, "ECO_SOCKET": str(local), "ECO_ADDR": target,
               "ECO_KEY": str(base/"eco-client"), "ECO_PEER": server_key}
        tcp_env = {**env, "ECO_BULK_TCP": "1"}
        server = stack.enter_context(background("serve", target, base/"eco-server", base/"eco-clients", base, "run", env=tcp_env))
        assert b"listening" in server.stderr.readline()
        client = stack.enter_context(background("client", local, target, base/"eco-client", server_key, env=env))
        wait_ready(local, client)
        ssh_home = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="ssh-eco-", dir=Path.cwd().parent)))
        sshd, ssh_master, ssh_worker, ssh, scp_options, port = ssh_session(stack, ssh_home, base/"ctl")
        source = base/"fixture"
        source.write_bytes(os.urandom(arguments.size_mib*1024*1024))
        expected = hashlib.sha256(source.read_bytes()).digest()
        run = struct.pack("<IBHH", 10000, 0, 0, 0) + b".\0/usr/bin/true\0"
        stat_args = ["-f", "%z"] if sys.platform == "darwin" else ["-c", "%s"]
        stat_args += [str(source)]
        session = stack.enter_context(socket.socket(socket.AF_UNIX))
        session.settimeout(5)
        session.connect(str(local))
        send_message(session, 23)
        assert read_message(session) == bytes([39])

        def ssh_request(command):
            ssh_worker.stdin.write(json.dumps(command) + "\n")
            ssh_worker.stdin.flush()
            assert json.loads(ssh_worker.stdout.readline())[0] == 0

        def native_run():
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(5)
                sock.connect(str(local))
                local_request(sock, 8, run)

        cases = {
            "Odin ping / persistent IPC": lambda: local_request(session, 1),
            "Odin stat / persistent IPC": lambda: local_request(session, 2, b"fixture"),
            "SSH stat / persistent worker": lambda: ssh_request(["/usr/bin/stat", *stat_args]),
            "Odin true / warm daemon": native_run,
            "SSH true / persistent worker": lambda: ssh_request(["/usr/bin/true"]),
            "SSH true / ControlMaster": lambda: cli_call([*ssh, "127.0.0.1", "/usr/bin/true"]),
            "Odin ping / fresh CLI": lambda: cli("ping", env=env),
        }
        for action in cases.values():
            action()
        print(f"Warm idle RSS. Odin server/client {rss_group(server):.2f}/{rss_group(client):.2f} MiB, "
              f"OpenSSH server tree/client tree {rss_group(sshd, descend=True):.2f}/"
              f"{rss_group(ssh_master, ssh_worker, descend=True):.2f} MiB", flush=True)
        results = defaultdict(list)
        rng = random.Random(17)
        for _ in range(arguments.samples):
            order = list(cases)
            rng.shuffle(order)
            for label in order:
                sample(results, label, cases[label])
        summarize(results)

        download = base/"download"
        transfers = {
            "Odin UDP verified get": lambda: cli("get", "fixture", download, env=env, timeout=40),
            "Odin TCP verified get": lambda: cli("get", "fixture", download, env=tcp_env, timeout=40),
            "OpenSSH SFTP / ControlMaster": lambda: cli_call(
                ["scp", *scp_options, "-P", str(port), f"127.0.0.1:{source}", download]
            ),
        }
        results.clear()
        for _ in range(4):
            order = list(transfers)
            rng.shuffle(order)
            for label in order:
                sample(results, label, transfers[label])
                assert hashlib.sha256(download.read_bytes()).digest() == expected
                download.unlink()
        summarize(results, arguments.size_mib)


if __name__ == "__main__":
    main()
