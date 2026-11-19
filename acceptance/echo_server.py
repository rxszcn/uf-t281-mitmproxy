"""Zero-dependency loopback echo server for export-command replay verification.

For every request it writes the raw, reassembled HTTP/1 request (request line +
headers + body) back as the response body, prefixed with ``ECHO\\n`` so a client
can locate it. Only listens on 127.0.0.1. Standard library only.
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class EchoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _echo(self) -> None:
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length) if length else b""
        prefix = b"ECHO\n"
        head = (
            f"{self.command} {self.path} {self.request_version}\r\n".encode("latin-1")
        )
        header_lines = b"".join(
            f"{k}: {v}\r\n".encode("latin-1") for k, v in self.headers.items()
        )
        payload = prefix + head + header_lines + b"\r\n" + body
        self.send_response(200)
        self.send_header("content-type", "application/octet-stream")
        self.send_header("content-length", str(len(payload)))
        # One response per connection so a client subprocess never has to
        # demultiplex several responses from one stdout stream.
        self.send_header("connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _echo  # type: ignore[assignment]

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = HTTPServer(("127.0.0.1", port), EchoHandler)
    print(f"echo server on http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
