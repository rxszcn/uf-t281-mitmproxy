"""Forensic export replay acceptance harness.

Runs the curl/httpie commands produced by mitmproxy's exporter against a
loopback echo server and compares the replayed request body byte-for-byte
with the recorded input, for five constructed inputs:

  1. percent-encoded / template-placeholder body (with a control char)
  2. Windows path body containing backslashes (with a control char)
  3. body ending in a newline
  4. body starting with "@"
  5. control group: plain body without control characters

Every command is executed under both bash and a POSIX-only dash. The harness
uses only the Python standard library plus the mitmproxy package under test;
the echo server (echo_server.py) is standard library as well.

Usage:
    # terminal 1
    .venv/Scripts/python -I acceptance/echo_server.py 8765
    # terminal 2
    .venv/Scripts/python -I acceptance/acceptance_run.py
"""

from __future__ import annotations

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mitmproxy.addons import export  # noqa: E402
from mitmproxy.test import taddons, tflow, tutils  # noqa: E402

from replay_lib import extract_echo  # noqa: E402

PORT = 8765

# The five constructed inputs required by the task statement. Each entry is
# (label, recorded body bytes, optional content-type header).
CONSTRUCTED_INPUTS: list[tuple[str, bytes, tuple[bytes, bytes] | None]] = [
    (
        "class1_percent_encoding_and_template",
        b"search=%2fhome&tpl={{user}}/profile&pct=%x&id=99%d\n",
        None,
    ),
    (
        "class2_windows_path_backslashes",
        b"path=C:\\tmp\\new\\report.txt\n",
        None,
    ),
    ("class3_trailing_newline", b"line1\nline2\n", None),
    ("class4_at_prefix", b"@replay-token: keep me", None),
    (
        "control_group_no_control_chars",
        b"simple-body-123",
        None,
    ),
]

SHELLS = (
    ("bash", r"C:\Program Files\Git\bin\bash.exe"),
    ("dash", r"C:\Program Files\Git\usr\bin\dash.exe"),
)

ENV = {
    **os.environ,
    "PATH": (
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        + r"\.venv\Scripts;C:\Windows\System32;C:\Windows;"
        r"C:\Program Files\Git\usr\bin;C:\Program Files\Git\mingw64\bin"
    ),
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
}


def first_difference(got: bytes, want: bytes) -> str:
    for index, (a, b) in enumerate(zip(got, want)):
        if a != b:
            return (
                f"first diff at byte {index}: got 0x{a:02x} want 0x{b:02x}; "
                f"length got={len(got)} want={len(want)}"
            )
    if len(got) != len(want):
        return f"identical prefix; length got={len(got)} want={len(want)}"
    return "no difference"


def build_flow(body: bytes, content_type: tuple[bytes, bytes] | None):
    headers = (content_type,) if content_type else ()
    return tflow.tflow(
        req=tutils.treq(
            method=b"POST",
            headers=headers,
            content=body,
            host=b"127.0.0.1",
            port=PORT,
            path=b"/ingest",
        )
    )


def main() -> int:
    exporters = (("curl", export.curl_command), ("httpie", export.httpie_command))
    e = export.Export()
    failures = 0
    total = 0
    with taddons.context() as tctx:
        tctx.configure(e)
        for label, body, content_type in CONSTRUCTED_INPUTS:
            flow = build_flow(body, content_type)
            print(f"=== {label} ===")
            print(f"recorded bytes ({len(body)}): {body!r}")
            for fmt_name, formatter in exporters:
                command = formatter(flow)
                print(f"[{fmt_name}] {command}")
                for shell_label, shell_path in SHELLS:
                    total += 1
                    result = subprocess.run(
                        [shell_path, "-c", command],
                        capture_output=True,
                        env=ENV,
                    )
                    try:
                        replayed = extract_echo(result.stdout)
                    except ValueError:
                        replayed = None
                    if replayed == body:
                        print(f"  {shell_label:4s}: CONSISTENT (byte-exact)")
                    else:
                        failures += 1
                        if replayed is None:
                            detail = (
                                "request not sent / no echo: "
                                + result.stderr.decode("replace").strip()[:160]
                            )
                        else:
                            detail = first_difference(replayed, body)
                            detail += f" | replayed={replayed!r}"
                        print(f"  {shell_label:4s}: INCONSISTENT -> {detail}")
            print()
    print(f"summary: {total - failures}/{total} byte-exact, {failures} failing")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
