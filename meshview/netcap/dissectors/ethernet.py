"""
Ethernet II frame dissector.

Frame layout (no 802.1Q tag):

    +----------------+----------------+-----------+---------+
    | dst mac (6)    | src mac (6)    | type (2)  | payload |
    +----------------+----------------+-----------+---------+

We also unwrap a single 802.1Q VLAN tag (EtherType 0x8100) since it's
common on real capture interfaces, though the VLAN id itself isn't
surfaced anywhere else yet.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

HEADER_LEN = 14


class DissectionError(ValueError):
    """Raised when a buffer is too short or malformed for a given layer."""


@dataclass
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    vlan_id: int | None
    payload: bytes

    @property
    def ethertype_hex(self) -> str:
        return f"0x{self.ethertype:04x}"


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def dissect_ethernet(raw: bytes) -> EthernetFrame:
    if len(raw) < HEADER_LEN:
        raise DissectionError(f"frame too short for an Ethernet header: {len(raw)} bytes")

    dst_mac = _format_mac(raw[0:6])
    src_mac = _format_mac(raw[6:12])
    ethertype = struct.unpack("!H", raw[12:14])[0]
    offset = HEADER_LEN
    vlan_id = None

    if ethertype == ETHERTYPE_VLAN:
        if len(raw) < offset + 4:
            raise DissectionError("frame too short for an 802.1Q tag")
        tci, inner_type = struct.unpack("!HH", raw[offset:offset + 4])
        vlan_id = tci & 0x0FFF
        ethertype = inner_type
        offset += 4

    return EthernetFrame(
        dst_mac=dst_mac,
        src_mac=src_mac,
        ethertype=ethertype,
        vlan_id=vlan_id,
        payload=raw[offset:],
    )
