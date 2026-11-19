import logging
import shlex
from collections.abc import Callable
from collections.abc import Sequence

import pyperclip

import mitmproxy.types
from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import http
from mitmproxy.net.http.http1 import assemble
from mitmproxy.utils import strutils


def cleanup_request(f: flow.Flow) -> http.Request:
    if not getattr(f, "request", None):
        raise exceptions.CommandError("Can't export flow with no request.")
    assert isinstance(f, http.HTTPFlow)
    request = f.request.copy()
    request.decode(strict=False)
    return request


def pop_headers(request: http.Request) -> None:
    """Remove some headers that are redundant for curl/httpie export."""
    request.headers.pop("content-length", None)

    if request.headers.get("host", "") == request.host:
        request.headers.pop("host")
    if request.headers.get(":authority", "") == request.host:
        request.headers.pop(":authority")


def cleanup_response(f: flow.Flow) -> http.Response:
    if not getattr(f, "response", None):
        raise exceptions.CommandError("Can't export flow with no response.")
    assert isinstance(f, http.HTTPFlow)
    response = f.response.copy()  # type: ignore
    response.decode(strict=False)
    return response


def _request_text(request: http.Request) -> str:
    try:
        text = request.get_text(strict=True)
        assert text
    except ValueError:
        # shlex.quote doesn't support a bytes object
        # see https://github.com/python/cpython/pull/10871
        raise exceptions.CommandError("Request content must be valid unicode")
    return text


def request_content_for_console(request: http.Request) -> str:
    """Quote a request body for direct placement on a curl/httpie command line.

    This is only safe for "simple" bodies: bodies without ASCII control
    characters and bodies that do not begin with ``@``. A literal ``@`` prefix
    would make curl interpret the argument as a file reference (``-d @file``),
    and control characters cannot be represented faithfully as a plain
    argument. Such bodies are handled by :func:`request_body_pipe`.
    """
    return shlex.quote(_request_text(request))


def _needs_pipe_encoding(text: str) -> bool:
    return text.startswith("@") or any(ord(char) < 32 for char in text)


def request_body_pipe(request: http.Request) -> str:
    """Return a shell snippet that emits the request body on stdout, byte for byte.

    The snippet has the form::

        printf '<format string>' '<arg>' ...

    and is intended to be piped into the replaying tool (``curl --data-binary
    @-`` / httpie on stdin). Rationale for the construction:

    * ``printf '<body>'`` (the previous approach) passes the recorded body as
      the *format string*, so percent sequences such as ``%2f`` or ``%x`` are
      consumed as conversions, and command substitution (``"$(...)"``) strips
      every trailing newline.
    * The body is therefore split into literal text segments and control
      characters. Literal segments are emitted through ``%s`` conversions, so
      neither ``%`` nor backslashes (as in Windows paths like ``C:\\tmp``) are
      ever interpreted; each control character gets its own ``%b`` conversion
      paired with a three-digit octal ``\\0NN`` argument, which every POSIX
      ``printf`` decodes to exactly that byte.
    * Piping stdout into the tool avoids both curl's ``@file`` interpretation
      of an at-prefixed body and curl's newline stripping with plain ``-d``;
      ``--data-binary @-`` forwards the piped bytes unchanged. It also keeps
      the command POSIX-shell compatible, unlike bash-only here-strings
      (``<<<``), which additionally append a newline.
    """
    text = _request_text(request)
    format_parts: list[str] = []
    arguments: list[str] = []
    literal: list[str] = []

    def flush_literal() -> None:
        if literal:
            format_parts.append("%s")
            arguments.append("".join(literal))
            literal.clear()

    for char in text:
        code = ord(char)
        if code < 32:
            flush_literal()
            format_parts.append("%b")
            arguments.append(f"\\{code:03o}")
        else:
            literal.append(char)
    flush_literal()

    # Trailing no-op conversion with an empty argument. Some printf builds
    # (observed with Git for Windows' dash/bash) do not restart the format
    # string on extra arguments when the format ends in a conversion
    # specifier; instead they feed surplus arguments into the trailing
    # conversion. A final "%s" paired with an empty argument emits no bytes
    # while making the format end cleanly, so every body segment maps to its
    # own conversion on every POSIX shell.
    format_parts.append("%s")
    arguments.append("")

    return "printf " + shlex.quote("".join(format_parts)) + " " + " ".join(
        shlex.quote(argument) for argument in arguments
    )


def curl_command(f: flow.Flow) -> str:
    request = cleanup_request(f)
    pop_headers(request)

    args = ["curl"]

    server_addr = f.server_conn.peername[0] if f.server_conn.peername else None

    if (
        ctx.options.export_preserve_original_ip
        and server_addr
        and request.pretty_host != server_addr
    ):
        resolve = f"{request.pretty_host}:{request.port}:[{server_addr}]"
        args.append("--resolve")
        args.append(resolve)

    for k, v in request.headers.items(multi=True):
        if k.lower() == "accept-encoding":
            args.append("--compressed")
        else:
            args += ["-H", f"{k}: {v}"]

    if request.method != "GET":
        if not request.content:
            # curl will not calculate content-length if there is no content
            # some server/verb combinations require content-length headers
            # (ex. nginx and POST)
            args += ["-H", "content-length: 0"]

        args += ["-X", request.method]

    args.append(request.pretty_url)

    command = " ".join(shlex.quote(arg) for arg in args)
    if request.content:
        body_text = _request_text(request)
        if _needs_pipe_encoding(body_text):
            # Pipe the body byte-for-byte: --data-binary @- neither strips
            # newlines nor interprets a leading "@" as a file reference.
            command = (
                f"{request_body_pipe(request)} | {command} --data-binary @-"
            )
        else:
            command += f" -d {request_content_for_console(request)}"
    return command


def httpie_command(f: flow.Flow) -> str:
    request = cleanup_request(f)
    pop_headers(request)

    # TODO: Once https://github.com/httpie/httpie/issues/414 is implemented, we
    # should ensure we always connect to the IP address specified in the flow,
    # similar to how it's done in curl_command.
    url = request.pretty_url

    args = ["http", request.method, url]
    for k, v in request.headers.items(multi=True):
        args.append(f"{k}: {v}")
    cmd = " ".join(shlex.quote(arg) for arg in args)
    if request.content:
        # Always pipe the body: here-strings ("<<<") are bash-only (a syntax
        # error in a POSIX shell) and append an extra newline, so they can
        # never reproduce the recorded bytes. The same pipe criterion as in
        # curl_command applies; simple bodies are emitted with a single
        # "printf %s" segment.
        cmd = f"{request_body_pipe(request)} | {cmd}"
    return cmd


def raw_request(f: flow.Flow) -> bytes:
    request = cleanup_request(f)
    if request.raw_content is None:
        raise exceptions.CommandError("Request content missing.")
    return assemble.assemble_request(request)


def raw_response(f: flow.Flow) -> bytes:
    response = cleanup_response(f)
    if response.raw_content is None:
        raise exceptions.CommandError("Response content missing.")
    return assemble.assemble_response(response)


def raw(f: flow.Flow, separator=b"\r\n\r\n") -> bytes:
    """Return either the request or response if only one exists, otherwise return both"""
    request_present = (
        isinstance(f, http.HTTPFlow) and f.request and f.request.raw_content is not None
    )
    response_present = (
        isinstance(f, http.HTTPFlow)
        and f.response
        and f.response.raw_content is not None
    )

    if request_present and response_present:
        parts = [raw_request(f), raw_response(f)]
        if isinstance(f, http.HTTPFlow) and f.websocket:
            parts.append(f.websocket._get_formatted_messages())
        return separator.join(parts)
    elif request_present:
        return raw_request(f)
    elif response_present:
        return raw_response(f)
    else:
        raise exceptions.CommandError("Can't export flow with no request or response.")


formats: dict[str, Callable[[flow.Flow], str | bytes]] = dict(
    curl=curl_command,
    httpie=httpie_command,
    raw=raw,
    raw_request=raw_request,
    raw_response=raw_response,
)


class Export:
    def load(self, loader):
        loader.add_option(
            "export_preserve_original_ip",
            bool,
            False,
            """
            When exporting a request as an external command, make an effort to
            connect to the same IP as in the original request. This helps with
            reproducibility in cases where the behaviour depends on the
            particular host we are connecting to. Currently this only affects
            curl exports.
            """,
        )

    @command.command("export.formats")
    def formats(self) -> Sequence[str]:
        """
        Return a list of the supported export formats.
        """
        return list(sorted(formats.keys()))

    @command.command("export.file")
    def file(self, format: str, flow: flow.Flow, path: mitmproxy.types.Path) -> None:
        """
        Export a flow to path.
        """
        if format not in formats:
            raise exceptions.CommandError("No such export format: %s" % format)
        v = formats[format](flow)
        try:
            with open(path, "wb") as fp:
                if isinstance(v, bytes):
                    fp.write(v)
                else:
                    fp.write(v.encode("utf-8", "surrogateescape"))
        except OSError as e:
            logging.error(str(e))

    @command.command("export.clip")
    def clip(self, format: str, f: flow.Flow) -> None:
        """
        Export a flow to the system clipboard.
        """
        content = self.export_str(format, f)
        try:
            pyperclip.copy(content)
        except pyperclip.PyperclipException as e:
            logging.error(str(e))

    @command.command("export")
    def export_str(self, format: str, f: flow.Flow) -> str:
        """
        Export a flow and return the result.
        """
        if format not in formats:
            raise exceptions.CommandError("No such export format: %s" % format)

        content = formats[format](f)
        # The individual formatters may return surrogate-escaped UTF-8, but that may blow up in later steps.
        # For example, pyperclip on macOS does not like surrogates.
        # To fix this, We first surrogate-encode and then backslash-decode.
        content = strutils.always_bytes(content, "utf8", "surrogateescape")
        content = strutils.always_str(content, "utf8", "backslashreplace")
        return content
