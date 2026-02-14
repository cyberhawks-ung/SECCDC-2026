#!/usr/bin/env python3
"""
AltAcctee Client - Connect to backup access servers from management machine.
"""

import argparse
import base64
import json
import os
import socket
import sys
import threading
from datetime import datetime, timezone

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


def find_hosts_config() -> str | None:
    """Find hosts.json in cwd or ~/.altacctee/hosts.json."""
    for path in [
        os.path.join(os.getcwd(), "hosts.json"),
        os.path.expanduser("~/.altacctee/hosts.json"),
    ]:
        if os.path.isfile(path):
            return path
    return None


def load_hosts(config_path: str | None = None) -> list[dict]:
    """Load host list from config file."""
    path = config_path or find_hosts_config()
    if not path:
        return []
    with open(path) as f:
        data = json.load(f)
    return data.get("hosts", [])


def filter_hosts(hosts: list[dict], host: str | None, os_filter: str | None, hosts_list: list[str] | None) -> list[dict]:
    """Filter hosts by --host, --os, or --hosts."""
    if hosts_list:
        ips = {h.strip() for h in hosts_list if h.strip()}
        return [h for h in hosts if h.get("ip") in ips]
    if host:
        return [h for h in hosts if h.get("ip") == host]
    if os_filter:
        return [h for h in hosts if h.get("os", "").lower() == os_filter.lower()]
    return hosts


LOG_DIR = os.path.expanduser("~/.altacctee/logs")
MAX_LOG_OUTPUT = 500


def _sanitize_machine_name(ip: str) -> str:
    """Sanitize IP/hostname for use as log filename."""
    return ip.replace(".", "_").replace(":", "_")


def _get_log_path(machine: str, log_dir: str) -> str:
    """Get log file path for a machine."""
    log_dir = os.path.abspath(os.path.expanduser(log_dir))
    os.makedirs(log_dir, mode=0o700, exist_ok=True)
    safe_name = _sanitize_machine_name(machine) or "unknown"
    return os.path.join(log_dir, "%s.log" % safe_name)


def log_command(machine: str, command: str, stdout: str, stderr: str, exit_code: int, log_dir: str) -> None:
    """Append a command execution to the machine's log file."""
    try:
        path = _get_log_path(machine, log_dir)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        combined = (stdout or "") + (stderr or "")
        if len(combined) > MAX_LOG_OUTPUT:
            output = combined[:MAX_LOG_OUTPUT] + "\n...[truncated, total %d chars]" % len(combined)
        else:
            output = combined or "(no output)"
        entry = (
            "=== %s ===\n"
            "INPUT: %s\n"
            "EXIT_CODE: %d\n"
            "OUTPUT:\n%s\n"
            "---\n"
        ) % (ts, command, exit_code, output)
        with open(path, "a", encoding="utf-8") as f:
            f.write(entry)
            f.flush()
    except OSError:
        pass


def connect_and_auth(ip: str, port: int, timeout: float = 10) -> socket.socket | None:
    """Connect to server and authenticate. Returns socket or None on failure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        send_message(sock, MSG_AUTH, {"password": PASSWORD})
        msg = read_message(sock)
        if msg is None:
            sock.close()
            return None
        msg_type, payload = msg
        if msg_type != MSG_AUTH_OK:
            sock.close()
            return None
        sock.settimeout(None)
        return sock
    except (socket.error, OSError):
        return None


def run_command(hosts: list[dict], command: str, log_dir: str | None = None) -> None:
    """Execute command on each host and print results."""
    log_dir = log_dir or LOG_DIR
    for h in hosts:
        ip = h.get("ip", "")
        port = int(h.get("port", DEFAULT_PORT))
        sock = connect_and_auth(ip, port)
        if sock is None:
            print("[%s] Connection failed" % ip, file=sys.stderr)
            continue
        try:
            send_message(sock, MSG_EXEC, {"command": command})
            msg = read_message(sock)
            if msg is None:
                print("[%s] No response" % ip, file=sys.stderr)
                continue
            msg_type, payload = msg
            if msg_type != MSG_EXEC_RESULT:
                print("[%s] Unexpected response" % ip, file=sys.stderr)
                continue
            stdout = payload.get("stdout", "")
            stderr = payload.get("stderr", "")
            exit_code = payload.get("exit_code", -1)
            log_command(ip, command, stdout, stderr, exit_code, log_dir)
            print("[%s] (exit %d)" % (ip, exit_code))
            if stdout:
                print(stdout, end="" if stdout.endswith("\n") else "\n")
            if stderr:
                print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)
        finally:
            sock.close()


def run_shell(ip: str, port: int, log_dir: str | None = None) -> None:
    """Interactive shell to single host."""
    log_dir = log_dir or LOG_DIR

    sock = connect_and_auth(ip, port)
    if sock is None:
        print("Connection failed to %s:%d" % (ip, port), file=sys.stderr)
        sys.exit(1)

    send_message(sock, MSG_SHELL_START, {})

    # Shared state for shell session logging
    log_lock = threading.Lock()
    input_buffer = bytearray()
    output_buffer: list[str] = []
    pending_command: str | None = None

    def flush_log(command: str, output: str) -> None:
        with log_lock:
            try:
                path = _get_log_path(ip, log_dir)
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                if len(output) > MAX_LOG_OUTPUT:
                    out = output[:MAX_LOG_OUTPUT] + "\n...[truncated, total %d chars]" % len(output)
                else:
                    out = output or "(no output)"
                entry = (
                    "=== %s (shell) ===\n"
                    "INPUT: %s\n"
                    "OUTPUT:\n%s\n"
                    "---\n"
                ) % (ts, command, out)
                with open(path, "a", encoding="utf-8") as f:
                    f.write(entry)
                    f.flush()
            except OSError:
                pass

    def on_send(data: bytes) -> None:
        nonlocal pending_command
        input_buffer.extend(data)
        while b"\n" in input_buffer or b"\r" in input_buffer:
            idx = input_buffer.find(b"\n")
            if idx < 0:
                idx = input_buffer.find(b"\r")
            if idx < 0:
                break
            line = bytes(input_buffer[: idx + 1]).decode("utf-8", errors="replace").strip()
            del input_buffer[: idx + 1]
            if not line:
                continue
            with log_lock:
                out = "".join(output_buffer)
                output_buffer.clear()
            if pending_command is not None:
                flush_log(pending_command, out)
            pending_command = line

    def on_receive(data: bytes) -> None:
        with log_lock:
            output_buffer.append(data.decode("utf-8", errors="replace"))

    def on_exit() -> None:
        nonlocal pending_command
        with log_lock:
            out = "".join(output_buffer)
        if pending_command is not None:
            flush_log(pending_command, out)

    def socket_to_stdout():
        try:
            while True:
                msg = read_message(sock)
                if msg is None:
                    break
                msg_type, payload = msg
                if msg_type == MSG_SHELL_DATA:
                    data = base64.b64decode(payload.get("data", ""))
                    on_receive(data)
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

    def stdin_to_socket():
        try:
            while True:
                data = sys.stdin.buffer.read1(4096)
                if not data:
                    on_exit()
                    send_message(sock, MSG_SHELL_END, {})
                    break
                on_send(data)
                send_message(sock, MSG_SHELL_DATA, {"data": base64.b64encode(data).decode()})
        except (ConnectionResetError, BrokenPipeError, OSError):
            on_exit()

    # Use threads: one reads from socket -> stdout, one reads stdin -> socket
    t = threading.Thread(target=socket_to_stdout, daemon=True)
    t.start()
    stdin_to_socket()
    sock.close()


def main():
    parser = argparse.ArgumentParser(description="AltAcctee backup access client")
    parser.add_argument("-c", "--config", help="Path to hosts.json")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Execute command on hosts")
    run_parser.add_argument("command_text", nargs="+", metavar="command", help="Command to run")
    run_parser.add_argument("--host", help="Target single host by IP")
    run_parser.add_argument("--os", choices=["linux", "windows"], help="Target hosts by OS")
    run_parser.add_argument("--hosts", help="Comma-separated list of IPs")
    run_parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Port (for --hosts)")
    run_parser.add_argument("--log-dir", default=LOG_DIR, help="Directory for per-machine log files (default: ~/.altacctee/logs)")

    shell_parser = subparsers.add_parser("shell", help="Interactive shell to host")
    shell_parser.add_argument("--host", required=True, help="Target host IP")
    shell_parser.add_argument("-p", "--port", type=int, default=None, help="Port (default from config)")
    shell_parser.add_argument("--log-dir", default=LOG_DIR, help="Directory for per-machine log files")

    args = parser.parse_args()

    hosts = load_hosts(args.config)
    if not hosts and args.command != "shell" and not getattr(args, "hosts", None):
        print("No hosts.json found. Create one, use -c /path/to/hosts.json, or use --hosts", file=sys.stderr)
        sys.exit(1)

    if args.command == "run":
        run_args = args
        if run_args.hosts:
            ips = {h.strip() for h in run_args.hosts.split(",") if h.strip()}
            filtered = [h for h in hosts if h.get("ip") in ips]
            for ip in ips:
                if not any(h.get("ip") == ip for h in filtered):
                    filtered.append({"ip": ip, "port": run_args.port or DEFAULT_PORT, "os": "unknown"})
        else:
            filtered = filter_hosts(hosts, run_args.host, run_args.os, None)
        if not filtered:
            print("No hosts match. Use --host, --os, or --hosts", file=sys.stderr)
            sys.exit(1)
        cmd = " ".join(run_args.command_text)
        run_command(filtered, cmd, getattr(run_args, "log_dir", None))

    elif args.command == "shell":
        ip = args.host
        port = args.port
        if port is None:
            for h in hosts:
                if h.get("ip") == ip:
                    port = int(h.get("port", DEFAULT_PORT))
                    break
            port = port or DEFAULT_PORT
        run_shell(ip, port, getattr(args, "log_dir", None))


if __name__ == "__main__":
    main()
