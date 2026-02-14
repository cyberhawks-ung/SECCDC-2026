"""
Shared protocol for AltAcctee client-server communication.
Uses newline-delimited JSON messages.
"""

import json

# Message types
MSG_AUTH = "auth"
MSG_AUTH_OK = "auth_ok"
MSG_AUTH_FAIL = "auth_fail"
MSG_EXEC = "exec"
MSG_EXEC_RESULT = "exec_result"
MSG_SHELL_START = "shell_start"
MSG_SHELL_DATA = "shell_data"
MSG_SHELL_END = "shell_end"

# Authentication
PASSWORD = "CyberHawksRulez"

# Default port
DEFAULT_PORT = 44158


def encode_message(msg_type: str, payload: dict) -> bytes:
    """Encode a message as JSON line."""
    msg = {"type": msg_type, "payload": payload}
    return (json.dumps(msg) + "\n").encode("utf-8")


def decode_message(data: bytes) -> tuple[str, dict]:
    """Decode a JSON message. Returns (type, payload)."""
    line = data.decode("utf-8").strip()
    msg = json.loads(line)
    return msg["type"], msg.get("payload", {})


def read_message(sock) -> tuple[str, dict] | None:
    """Read a newline-delimited JSON message from socket. Returns None on EOF."""
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            return decode_message(line)


def send_message(sock, msg_type: str, payload: dict) -> None:
    """Send a message to the socket."""
    sock.sendall(encode_message(msg_type, payload))
