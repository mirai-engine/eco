"""Exercise ECO end to end on an interactive Windows x64 host with Python 3."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import csv
import ctypes
from ctypes import wintypes
import msvcrt
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid

if sys.platform == "win32":
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel.WaitNamedPipeW.restype = wintypes.BOOL
    kernel.PeekNamedPipe.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel.PeekNamedPipe.restype = wintypes.BOOL
    kernel.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    kernel.GetNamedPipeServerProcessId.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL


def await_pipe(name, process):
    until = time.monotonic() + 5
    while time.monotonic() < until and process.poll() is None:
        if kernel.WaitNamedPipeW(name, 50):
            return
        time.sleep(0.02)
    raise AssertionError(f"Named Pipe did not start ({process.poll()})")


def read_exact(pipe, size, deadline):
    data = bytearray()
    handle = msvcrt.get_osfhandle(pipe.fileno())
    while len(data) < size:
        available = wintypes.DWORD()
        if not kernel.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if available.value:
            part = pipe.read(min(available.value, size-len(data)))
            if not part:
                raise EOFError("Named Pipe closed")
            data += part
        else:
            if time.monotonic() >= deadline:
                raise TimeoutError("Timed out reading from Named Pipe")
            time.sleep(0.005)
    return bytes(data)


def receive(pipe, deadline):
    size = int.from_bytes(read_exact(pipe, 2, deadline), "little")
    assert 0 < size <= 1136
    frame = read_exact(pipe, size, deadline)
    if frame[0] == 38:
        raise AssertionError(frame[1:].decode(errors="replace"))
    return frame[0], frame[1:]


def transmit(pipe, op, body=b""):
    frame = struct.pack("<HB", len(body)+1, op) + body
    assert pipe.write(frame) == len(frame)


def check_pty(name):
    command = (
        "import os,sys; "
        "print('ECO_READY', flush=True); sys.stdin.readline(); "
        "sz=os.get_terminal_size(); print(f'ECO_SIZE_{sz.columns}_{sz.lines}', flush=True)"
    )
    body = struct.pack("<IBHH", 10000, 1, 25, 80) + (
        "\0".join([".", sys.executable, "-u", "-c", command]) + "\0"
    ).encode()
    with open(name, "r+b", buffering=0) as pipe:
        transmit(pipe, 9, body)
        output = bytearray()
        deadline = time.monotonic() + 8
        while b"ECO_READY" not in output:
            op, data = receive(pipe, deadline)
            assert op == 32, (op, data)
            output += data
        transmit(pipe, 22, struct.pack("<HH", 30, 110))
        transmit(pipe, 20, b"\r")
        while True:
            op, data = receive(pipe, deadline)
            if op == 37:
                assert data == bytes(4), data
                break
            assert op == 32, (op, data)
            output += data
        assert b"ECO_SIZE_110_30" in output, output



def stop_test_daemon(name):
    # The generated pipe name belongs exclusively to this test.
    with open(name, "r+b", buffering=0) as pipe:
        pid = wintypes.ULONG()
        if not kernel.GetNamedPipeServerProcessId(msvcrt.get_osfhandle(pipe.fileno()), ctypes.byref(pid)):
            raise ctypes.WinError(ctypes.get_last_error())
        process = kernel.OpenProcess(1, False, pid.value)
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not kernel.TerminateProcess(process, 0):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.CloseHandle(process)


def check_tunnels(background, base, env):
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET, kind) as service, ThreadPoolExecutor(max_workers=1) as pool:
            service.bind(("127.0.0.1", 0))
            service.settimeout(8)
            if kind == socket.SOCK_STREAM:
                service.listen()

            def echo():
                if kind == socket.SOCK_DGRAM:
                    data, origin = service.recvfrom(1024)
                    service.sendto(data, origin)
                else:
                    conn, _ = service.accept()
                    with conn:
                        conn.settimeout(5)
                        data = bytearray()
                        for block in iter(lambda: conn.recv(1024), b""):
                            data += block
                        conn.sendall(data)

            expected = pool.submit(echo)
            with socket.socket(socket.AF_INET, kind) as reserve:
                reserve.bind(("127.0.0.1", 0))
                local = reserve.getsockname()[1]
            target = service.getsockname()[1]
            command = "forward" if kind == socket.SOCK_STREAM else "forward-udp"
            with background(command, f"127.0.0.1:{local}", f"127.0.0.1:{target}",
                            directory=base, env=env) as relay:
                payload = b"eco tunnel test" * 10
                deadline = time.monotonic() + 4
                while True:
                    assert relay.poll() is None
                    with socket.socket(socket.AF_INET, kind) as probe:
                        probe.settimeout(0.5)
                        address = ("127.0.0.1", local)
                        try:
                            if kind == socket.SOCK_DGRAM:
                                probe.sendto(payload, address)
                                output, _ = probe.recvfrom(1024)
                            else:
                                probe.connect(address)
                                probe.sendall(payload)
                                probe.shutdown(socket.SHUT_WR)
                                output = b"".join(iter(lambda: probe.recv(1024), b""))
                            assert output == payload
                            break
                        except (TimeoutError, ConnectionRefusedError):
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.02)
                expected.result(timeout=2)


def main():
    if sys.platform != "win32":
        raise SystemExit("This smoke test requires Windows.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path,
                        default=Path(__file__).resolve().parents[1] / "bin/eco-windows-amd64.exe")
    binary = parser.parse_args().binary.resolve()

    def run(*args, env=None, data=None, checked=True):
        result = subprocess.run([binary, *args], env=env, input=data, capture_output=True,
                                timeout=18, check=False)
        if checked:
            assert result.returncode == 0, (args, result.returncode, result.stderr)
        return result

    @contextmanager
    def background(*args, directory, env):
        with tempfile.TemporaryFile(dir=directory) as log:
            process = subprocess.Popen([binary, *args], env=env, stdout=log, stderr=log)
            try:
                yield process
            except BaseException:
                log.seek(0)
                print(log.read().decode(errors="replace"), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=5)

    with tempfile.TemporaryDirectory(prefix="eco-win-") as folder:
        base = Path(folder)
        root, jobs = base / "remote-é", base / "jobs"
        root.mkdir()
        jobs.mkdir()
        outside = base / "outside"
        outside.mkdir()
        (outside / "outside.txt").write_bytes(b"outside the scope")
        sid = next(csv.reader(subprocess.check_output(
            ["whoami", "/user", "/fo", "csv", "/nh"], text=True).splitlines()))[1]
        subprocess.run(["icacls", str(jobs), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
                       capture_output=True, check=True)

        server_key = base / "server.key"
        client_key = base / "client.key"
        server_public = run("keygen", server_key).stdout.decode().strip()
        client_public = run("keygen", client_key).stdout.decode().strip()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        address = f"127.0.0.1:{port}"
        pipe = r"\\.\pipe\eco-win-test-" + uuid.uuid4().hex
        env = {**os.environ, "ECO_ODIN_SOCKET": pipe, "ECO_ODIN_ADDR": address,
               "ECO_ODIN_KEY": str(client_key), "ECO_ODIN_PEER": server_public,
               "ECO_ODIN_JOBS": str(jobs)}
        env.pop("ECO_ODIN_CAPABILITY", None)
        env.pop("ECO_ODIN_BULK_TCP", None)
        bulk = {**env, "ECO_ODIN_BULK_TCP": "1"}
        server_args = ("serve", address, server_key, client_public, root, "run")
        client_args = ("client", pipe, address, client_key, server_public)
        with background(*server_args, directory=base, env=bulk):
            with background(*client_args, directory=base, env=env) as client:
                await_pipe(pipe, client)
                assert run("ping", env=env).stdout.startswith(b"pong")
                run("ping-early", address, client_key, server_public, env=env)

                data = bytes(range(256)) * 1000
                source, copied = base / "source-é", base / "copied-é"
                source.write_bytes(data)
                run("put", source, "payload-é", env=env)
                assert run("stat", "payload-é", env=env).stdout.startswith(b"file\t256000\t")
                assert run("get", "payload-é", copied, env=env).returncode == 0
                assert copied.read_bytes() == data
                run("put", source, "payload-é", env=bulk)  # Exercise atomic replacement.
                run("get", "payload-é", copied, env=bulk)
                assert copied.read_bytes() == data

                junction = root / "junction"
                subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
                               capture_output=True, check=True)
                try:
                    for path in ("../outside/outside.txt", "junction/outside.txt", "payload-é:stream"):
                        assert run("read", path, env=env, checked=False).returncode != 0
                finally:
                    os.rmdir(junction)

                command = ("run", "--", sys.executable, "-c",
                           "import sys;print(sys.argv[1]);print('err',file=sys.stderr);sys.exit(7)",
                           'spaces " quotes \\')
                result = run(*command, env=env, checked=False)
                assert result.returncode == 7 and result.stdout.strip() == b'spaces " quotes \\'
                assert result.stderr.strip() == b"err"
                echo = run("run", "--stdin", "--", sys.executable, "-c",
                           "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())", env=env, data=data)
                assert echo.stdout == data
                with ThreadPoolExecutor(max_workers=4) as pool:
                    assert all(item.stdout.startswith(b"pong") for item in
                               pool.map(lambda _: run("ping", env=env), range(8)))
                check_pty(pipe)
                check_tunnels(background, base, env)

                job = run("start", "--", sys.executable, "-c",
                          "import time;print('before',flush=True);time.sleep(2);print('after',flush=True)",
                          env=env).stdout.decode().strip()
                assert len(job) == 32, job

        with background(*server_args, directory=base, env=bulk):
            with background(*client_args, directory=base, env=env) as client:
                await_pipe(pipe, client)
                result = run("attach", job, env=env)
                assert result.stdout.splitlines() == [b"before", b"after"], result.stdout

        # Verify the CLI can start its own daemon under the same user's security descriptor.
        # A unique pipe name avoids touching an existing daemon.
        auto_env = {**env, "ECO_ODIN_SOCKET": pipe + "-auto"}
        with background(*server_args, directory=base, env=bulk):
            assert run("ping", env=auto_env).stdout.startswith(b"pong")
            stop_test_daemon(auto_env["ECO_ODIN_SOCKET"])

    print("Windows native ECO smoke passed")


if __name__ == "__main__":
    main()
