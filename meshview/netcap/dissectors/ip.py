"""
IPv4 header dissector.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-------+-------+---------------+-------------------------------+
   |Version|  IHL  |Type of Service|          Total Length          |
   +-------+-------+---------------+-------------------------------+
   |         Identification        |Flags|      Fragment Offset     |
   +---------------+---------------+-------------------------------+
   |  Time to Live |    Protocol   |         Header Checksum        |
   +---------------+---------------+---------------------------------+
   |                       Source Address                          |
   +-----------------------------------------------------------------+
   |                    Destination Address                        |
   +-----------------------------------------------------------------+
   |                    Options (if IHL > 5)                       |
   +-----------------------------------------------------------------+

IPv6 is out of scope for Phase 1 (see spec section 11, Limitations);
`dissect_ip` raises DissectionError for anything that isn't IPv4 so the
pipeline can fall back to an "OTHER" packet cleanly.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from .ethernet import DissectionError

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

MIN_HEADER_LEN = 20


@dataclass
class IPv4Packet:
    version: int
    header_len: int
    total_length: int
    ttl: int
    protocol: int
    src_ip: str
    dst_ip: str
    payload: bytes


def dissect_ip(raw: bytes) -> IPv4Packet:
    if len(raw) < MIN_HEADER_LEN:
        raise DissectionError(f"buffer too short for an IPv4 header: {len(raw)} bytes")

    version_ihl = raw[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    header_len = ihl * 4

    if version != 4:
        raise DissectionError(f"not IPv4 (version={version}); IPv6 is unsupported in Phase 1")
    if header_len < MIN_HEADER_LEN:
        raise DissectionError(f"invalid IHL: header length {header_len} < 20")
    if len(raw) < header_len:
        raise DissectionError("buffer too short for the declared IP header length")

    total_length = struct.unpack("!H", raw[2:4])[0]
    ttl = raw[8]
    protocol = raw[9]
    src_ip = str(ipaddress.IPv4Address(raw[12:16]))
    dst_ip = str(ipaddress.IPv4Address(raw[16:20]))

    return IPv4Packet(
        version=version,
        header_len=header_len,
        total_length=total_length,
        ttl=ttl,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        payload=raw[header_len:],
    )
