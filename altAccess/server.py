#!/usr/bin/env python3
"""
AltAcctee Server - Alternative access listener for blue team recovery.
Run as root (Linux) or Administrator (Windows) on each target machine.
"""

import argparse
import json
import os
import platform
import select
import socket
import socketserver
import subprocess
import sys
import threading

# Optional: pty is Unix-only
try:
    import pty
    HAS_PTY = True
except ImportError:
    HAS_PTY = False

from protocol import (
    DEFAULT_PORT,
    PASSWORD,
    MSG_AUTH,
    MSG_AUTH_OK,
    MSG_AUTH_FAIL,
    MSG_EXEC,
    MSG_EXEC_RESULT,
    MSG_SHELL_START,
    MSG_SHELL_DATA,
    MSG_SHELL_END,
    read_message,
    send_message,
)

IS_WINDOWS = platform.system() == "Windows"
SHELL = "powershell.exe" if IS_WINDOWS else "/bin/bash"
OS_NAME = platform.system()


def exec_command(cmd: str) -> tuple[str, str, int]:
    """Execute a command and return (stdout, stderr, exit_code)."""
    if IS_WINDOWS:
        proc = subprocess.run(
            [SHELL, "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=300,
        )
        return proc.stdout, proc.stderr, proc.returncode
    else:
        proc = subprocess.run(
            [SHELL, "-c", cmd],
            capture_output=True,
            text=True,
            timeout=300,
        )
        return proc.stdout, proc.stderr, proc.returncode


def handle_shell_linux(conn: socket.socket) -> None:
    """Interactive shell on Linux using PTY."""
    import base64
    import fcntl
    import termios

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm"
        os.execve(SHELL, [SHELL], os.environ)

    # Parent: relay between socket (protocol messages) and pty
    conn.setblocking(False)
    old_tty = termios.tcgetattr(fd)
    try:
        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
        pending = b""
        while True:
            rlist, _, _ = select.select([conn, fd], [], [], 0.5)
            for r in rlist:
                if r == conn:
                    try:
                        chunk = conn.recv(4096)
                        if not chunk:
                            return
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            msg = json.loads(line.decode("utf-8"))
                            if msg.get("type") == MSG_SHELL_END:
                                return
                            if msg.get("type") == MSG_SHELL_DATA:
                                data = base64.b64decode(msg.get("payload", {}).get("data", ""))
                                os.write(fd, data)
                    except (ConnectionResetError, BrokenPipeError, json.JSONDecodeError):
                        return
                elif r == fd:
                    try:
                        data = os.read(fd, 4096)
                        if not data:
                            return
                        send_message(conn, MSG_SHELL_DATA, {"data": base64.b64encode(data).decode()})
                    except OSError:
                        pass
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old_tty)
        os.close(fd)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


def handle_shell_windows(conn: socket.socket) -> None:
    """Interactive shell on Windows using subprocess."""
    import base64

    proc = subprocess.Popen(
        [SHELL, "-NoProfile", "-Command", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=False,
    )

    def socket_to_proc():
        try:
            while True:
                msg = read_message(conn)
                if msg is None:
                    break
                msg_type, payload = msg
                if msg_type == MSG_SHELL_END:
                    break
                if msg_type == MSG_SHELL_DATA:
                    data = base64.b64decode(payload.get("data", ""))
                    proc.stdin.write(data)
                    proc.stdin.flush()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                proc.stdin.close()
            except OSError:
                pass

    def proc_to_socket():
        try:
            while True:
                data = proc.stdout.read(4096)
                if not data:
                    break
                send_message(conn, MSG_SHELL_DATA, {"data": base64.b64encode(data).decode()})
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    t = threading.Thread(target=socket_to_proc, daemon=True)
    t.start()
    proc_to_socket()
    try:
        proc.terminate()
    except OSError:
        pass
    proc.wait(timeout=2)


def handle_client(conn: socket.socket) -> None:
    """Handle a single client connection."""
    try:
        conn.settimeout(30)
        msg = read_message(conn)
        if msg is None:
            return
        msg_type, payload = msg
        if msg_type != MSG_AUTH or payload.get("password") != PASSWORD:
            send_message(conn, MSG_AUTH_FAIL, {})
            return
        send_message(conn, MSG_AUTH_OK, {"os": OS_NAME})

        conn.settimeout(None)
        while True:
            msg = read_message(conn)
            if msg is None:
                break
            msg_type, payload = msg

            if msg_type == MSG_EXEC:
                cmd = payload.get("command", "")
                stdout, stderr, exit_code = exec_command(cmd)
                send_message(conn, MSG_EXEC_RESULT, {
                    "stdout": stdout or "",
                    "stderr": stderr or "",
                    "exit_code": exit_code,
                })

            elif msg_type == MSG_SHELL_START:
                if IS_WINDOWS:
                    handle_shell_windows(conn)
                else:
                    handle_shell_linux(conn)
                break

    except (ConnectionResetError, BrokenPipeError, OSError, json.JSONDecodeError) as e:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


class ThreadedTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        handle_client(self.request)


def main():
    parser = argparse.ArgumentParser(description="AltAcctee backup access server")
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=int(os.environ.get("ALTACCTEE_PORT", DEFAULT_PORT)),
        help="Port to listen on (default: %s)" % DEFAULT_PORT,
    )
    args = parser.parse_args()

    server = socketserver.ThreadingTCPServer(("0.0.0.0", args.port), ThreadedTCPHandler)
    server.daemon_threads = True
    print("AltAcctee server listening on port %d (%s)" % (args.port, OS_NAME), file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
