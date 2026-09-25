"""
TCP segment dissector.

    0                   1                   2                   3
    +-------------------------------+-------------------------------+
    |          Source Port          |       Destination Port        |
    +-------------------------------+-------------------------------+
    |                        Sequence Number                        |
    +-----------------------------------------------------------------+
    |                    Acknowledgment Number                      |
    +-------+-----+-------------------------------+-----------------+
    |Offset |Rsvd |  C E U A P R S F  |            Window            |
    +-------+-----+-------------------------------+-----------------+
    |            Checksum           |         Urgent Pointer         |
    +-------------------------------+-------------------------------+
    |                    Options (if Offset > 5)                    |
    +-----------------------------------------------------------------+

We decode flags and sequence numbers because the anomaly detector
(Phase 6) and the packet details pane both want them; options are
skipped over but not parsed field-by-field.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .ethernet import DissectionError

MIN_HEADER_LEN = 20

_FLAG_BITS = [
    ("FIN", 0x01),
    ("SYN", 0x02),
    ("RST", 0x04),
    ("PSH", 0x08),
    ("ACK", 0x10),
    ("URG", 0x20),
    ("ECE", 0x40),
    ("CWR", 0x80),
]


@dataclass
class TCPSegment:
    src_port: int
    dst_port: int
    seq: int
    ack: int
    header_len: int
    flags: set[str]
    window: int
    payload: bytes

    @property
    def flags_str(self) -> str:
        # Conventional display order, not the bit order in _FLAG_BITS.
        order = ["SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"]
        return ",".join(f for f in order if f in self.flags)


def dissect_tcp(raw: bytes) -> TCPSegment:
    if len(raw) < MIN_HEADER_LEN:
        raise DissectionError(f"buffer too short for a TCP header: {len(raw)} bytes")

    src_port, dst_port, seq, ack, offset_reserved_flags, window, _checksum, _urgent = (
        struct.unpack("!HHIIHHHH", raw[0:20])
    )

    data_offset = (offset_reserved_flags >> 12) & 0x0F
    header_len = data_offset * 4
    flag_byte = offset_reserved_flags & 0x00FF

    if header_len < MIN_HEADER_LEN:
        raise DissectionError(f"invalid TCP data offset: header length {header_len} < 20")
    if len(raw) < header_len:
        raise DissectionError("buffer too short for the declared TCP header length")

    flags = {name for name, bit in _FLAG_BITS if flag_byte & bit}

    return TCPSegment(
        src_port=src_port,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        header_len=header_len,
        flags=flags,
        window=window,
        payload=raw[header_len:],
    )
