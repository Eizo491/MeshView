"""
HTTP/1.x dissector.

HTTP is plain text over TCP, so this only makes sense to call on the
TCP payload of packets on a well-known HTTP port. It reads the
start-line and headers up to the blank line; it does not attempt to
reassemble a request/response split across multiple TCP segments
(each Packet row shows what that one segment contains).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ethernet import DissectionError

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}


@dataclass
class HTTPMessage:
    is_request: bool
    start_line: str
    method: str | None
    path: str | None
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)


def looks_like_http(payload: bytes) -> bool:
    if not payload:
        return False
    head = payload[:16]
    if head.startswith(b"HTTP/"):
        return True
    first_token = head.split(b" ", 1)[0].decode("ascii", errors="ignore")
    return first_token in HTTP_METHODS


def dissect_http(payload: bytes) -> HTTPMessage:
    if not looks_like_http(payload):
        raise DissectionError("payload does not look like HTTP/1.x")

    # Header block ends at the first blank line; body (if any) is ignored.
    header_block = payload.split(b"\r\n\r\n", 1)[0]
    try:
        text = header_block.decode("ascii", errors="replace")
    except Exception as exc:  # pragma: no cover - decode with errors="replace" won't raise
        raise DissectionError("could not decode HTTP header block") from exc

    lines = text.split("\r\n")
    start_line = lines[0]

    is_request = not start_line.startswith("HTTP/")
    method = path = None
    status_code = None

    if is_request:
        parts = start_line.split(" ")
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
    else:
        parts = start_line.split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()

    return HTTPMessage(
        is_request=is_request,
        start_line=start_line,
        method=method,
        path=path,
        status_code=status_code,
        headers=headers,
    )
