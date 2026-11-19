"""Shared helpers for acceptance replay checks (standard library only)."""

from __future__ import annotations

import subprocess


def extract_echo(response: bytes) -> bytes:
    """Extract the replayed request body from an echo-server response.

    The server writes the reassembled recorded request (request line +
    headers + blank line + body) prefixed by ``ECHO\\n`` directly as the
    outer response body. There is therefore exactly one CRLFCRLF boundary in
    the payload before the replayed body: the one terminating the *echoed
    request's* header block. The replayed body is everything after it, so
    bodies that themselves contain CR/LF or NUL are preserved whole.
    """
    if not response.startswith(b"ECHO\n"):
        raise ValueError("missing ECHO prefix")
    recorded = response[len(b"ECHO\n"):]
    marker = b"\r\n\r\n"
    sep = recorded.find(marker)
    if sep < 0:
        raise ValueError("echoed request has no header/body separator")
    return recorded[sep + len(marker):]


def run_shell(command: str, shell: str, env: dict[str, str]) -> tuple[bytes, bytes]:
    r = subprocess.run([shell, "-c", command], capture_output=True, env=env)
    return r.stdout, r.stderr
