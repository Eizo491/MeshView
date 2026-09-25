"""
DNS message dissector (RFC 1035 header + question section, plus a
best-effort read of answer records).

Header (12 bytes):

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                        |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |    RCODE    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

DNS names use compression: a two-byte pointer (top two bits set) can
replace the tail of a name with an offset into the whole message, so
name-reading needs the full message buffer, not just the remaining
slice -- that's why `dissect_dns` takes the complete UDP/TCP payload
and reads labels by absolute offset.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .ethernet import DissectionError

HEADER_LEN = 12
_MAX_POINTER_HOPS = 20  # guards against a malicious/malformed pointer loop

_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}


@dataclass
class DNSQuestion:
    name: str
    qtype: str


@dataclass
class DNSMessage:
    transaction_id: int
    is_response: bool
    opcode: int
    rcode: int
    question_count: int
    answer_count: int
    questions: list[DNSQuestion] = field(default_factory=list)


def _read_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Read a (possibly compressed) name starting at `offset`.

    Returns (name, offset_after_name). `offset_after_name` is the
    position right after this name *in the original, uncompressed
    sense* -- i.e. where the record's next field starts, even if the
    name itself jumped via a pointer partway through.
    """
    labels: list[str] = []
    pos = offset
    end_pos: int | None = None  # position to resume at once we've followed a pointer
    hops = 0

    while True:
        if pos >= len(msg):
            raise DissectionError("DNS name runs past end of message")
        length_byte = msg[pos]

        if length_byte == 0:
            pos += 1
            if end_pos is None:
                end_pos = pos
            break

        if length_byte & 0xC0 == 0xC0:
            if pos + 2 > len(msg):
                raise DissectionError("truncated DNS compression pointer")
            hops += 1
            if hops > _MAX_POINTER_HOPS:
                raise DissectionError("too many DNS compression pointer hops")
            pointer = struct.unpack("!H", msg[pos:pos + 2])[0] & 0x3FFF
            if end_pos is None:
                end_pos = pos + 2
            pos = pointer
            continue

        label_start = pos + 1
        label_end = label_start + length_byte
        if label_end > len(msg):
            raise DissectionError("DNS label runs past end of message")
        labels.append(msg[label_start:label_end].decode("ascii", errors="replace"))
        pos = label_end

    return ".".join(labels), end_pos


def dissect_dns(payload: bytes) -> DNSMessage:
    if len(payload) < HEADER_LEN:
        raise DissectionError(f"buffer too short for a DNS header: {len(payload)} bytes")

    transaction_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", payload[0:12]
    )
    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F

    questions: list[DNSQuestion] = []
    pos = HEADER_LEN
    for _ in range(qdcount):
        name, pos = _read_name(payload, pos)
        if pos + 4 > len(payload):
            raise DissectionError("truncated DNS question section")
        qtype_num, _qclass = struct.unpack("!HH", payload[pos:pos + 4])
        pos += 4
        questions.append(DNSQuestion(name=name, qtype=_QTYPES.get(qtype_num, str(qtype_num))))

    return DNSMessage(
        transaction_id=transaction_id,
        is_response=is_response,
        opcode=opcode,
        rcode=rcode,
        question_count=qdcount,
        answer_count=ancount,
        questions=questions,
    )
