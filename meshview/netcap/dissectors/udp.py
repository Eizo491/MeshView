"""
UDP segment dissector.

    +-------------------------------+-------------------------------+
    |          Source Port          |       Destination Port        |
    +-------------------------------+-------------------------------+
    |             Length             |            Checksum           |
    +-------------------------------+-------------------------------+
    |                             Payload                            |
    +-----------------------------------------------------------------+
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .ethernet import DissectionError

HEADER_LEN = 8


@dataclass
class UDPSegment:
    src_port: int
    dst_port: int
    length: int
    payload: bytes


def dissect_udp(raw: bytes) -> UDPSegment:
    if len(raw) < HEADER_LEN:
        raise DissectionError(f"buffer too short for a UDP header: {len(raw)} bytes")

    src_port, dst_port, length, _checksum = struct.unpack("!HHHH", raw[0:8])
    return UDPSegment(
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        payload=raw[HEADER_LEN:],
    )
