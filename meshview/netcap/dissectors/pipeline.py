"""
The dissector pipeline.

This is the one piece both the live-capture command (Phase 4) and the
PCAP importer (this phase) call: give it raw frame bytes plus a
timestamp and it returns a `DissectedPacket` ready to become a
`netcap.models.Packet` row. Keeping this logic here, instead of in
the importer or the capture command, is what makes "the rest of the
system doesn't care where the data came from" (spec section 5) true.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from . import dns as dns_dissector
from . import http as http_dissector
from . import ip as ip_dissector
from . import tcp as tcp_dissector
from . import udp as udp_dissector
from .ethernet import ETHERTYPE_IPV4, DissectionError, dissect_ethernet
from .ip import PROTO_ICMP, PROTO_TCP, PROTO_UDP

# Ports classified as plaintext / encrypted for the indicator described
# in spec section 9. Anything not listed here is left unclassified
# (encrypted=False) rather than guessed.
PLAINTEXT_PORTS = {80: "HTTP", 21: "FTP", 23: "Telnet"}
ENCRYPTED_PORTS = {443: "HTTPS", 22: "SSH"}
DNS_PORT = 53

PROTOCOL_NUMBER_NAMES = {PROTO_TCP: "TCP", PROTO_UDP: "UDP", PROTO_ICMP: "ICMP"}


@dataclass
class DissectedPacket:
    """Normalized fields, one-to-one with `netcap.models.Packet`."""

    timestamp: datetime
    length: int
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: str = ""
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "OTHER"
    ip_protocol_number: int | None = None
    encrypted: bool = False
    info: str = ""
    payload_preview: str = ""
    parse_error: str | None = None


def _preview(payload: bytes, max_bytes: int) -> str:
    """A short, display-safe preview: printable ASCII, others as '.'."""
    chunk = payload[:max_bytes]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def _classify_encryption(port_a: int | None, port_b: int | None) -> tuple[bool, str | None]:
    for port in (port_a, port_b):
        if port in ENCRYPTED_PORTS:
            return True, ENCRYPTED_PORTS[port]
        if port in PLAINTEXT_PORTS:
            return False, PLAINTEXT_PORTS[port]
    return False, None


def dissect_packet(
    raw: bytes,
    timestamp: datetime,
    payload_preview_bytes: int = 64,
) -> DissectedPacket:
    """Run the full Ethernet -> IP -> TCP/UDP -> DNS/HTTP chain.

    Never raises: a failure at any layer falls back to the best
    summary the earlier, successfully-parsed layers can give, with
    `parse_error` set so callers/tests can see it happened.
    """
    result = DissectedPacket(timestamp=timestamp, length=len(raw))

    try:
        frame = dissect_ethernet(raw)
    except DissectionError as exc:
        result.parse_error = f"ethernet: {exc}"
        result.info = "Malformed frame"
        return result

    result.src_mac = frame.src_mac
    result.dst_mac = frame.dst_mac
    result.ethertype = frame.ethertype_hex

    if frame.ethertype != ETHERTYPE_IPV4:
        # Anything that isn't IPv4 (ARP, IPv6, ...) stops here for Phase 1.
        result.protocol = "ARP" if frame.ethertype == 0x0806 else "OTHER"
        result.info = f"Non-IPv4 frame (ethertype {frame.ethertype_hex})"
        return result

    try:
        packet = ip_dissector.dissect_ip(frame.payload)
    except DissectionError as exc:
        result.parse_error = f"ip: {exc}"
        result.info = "Malformed IPv4 header"
        return result

    result.src_ip = packet.src_ip
    result.dst_ip = packet.dst_ip
    result.ip_protocol_number = packet.protocol
    result.protocol = PROTOCOL_NUMBER_NAMES.get(packet.protocol, "OTHER")
    result.info = f"{packet.src_ip} -> {packet.dst_ip}"

    if packet.protocol == PROTO_TCP:
        _dissect_tcp_layer(packet.payload, result, payload_preview_bytes)
    elif packet.protocol == PROTO_UDP:
        _dissect_udp_layer(packet.payload, result, payload_preview_bytes)
    else:
        result.payload_preview = _preview(packet.payload, payload_preview_bytes)

    return result


def _dissect_tcp_layer(payload: bytes, result: DissectedPacket, preview_bytes: int) -> None:
    try:
        segment = tcp_dissector.dissect_tcp(payload)
    except DissectionError as exc:
        result.parse_error = f"tcp: {exc}"
        result.info += " (malformed TCP header)"
        return

    result.src_port = segment.src_port
    result.dst_port = segment.dst_port
    result.encrypted, label = _classify_encryption(segment.src_port, segment.dst_port)
    result.info = f"{result.src_ip}:{segment.src_port} -> {result.dst_ip}:{segment.dst_port} [{segment.flags_str}]"
    result.payload_preview = _preview(segment.payload, preview_bytes)

    if http_dissector.looks_like_http(segment.payload):
        try:
            http_msg = http_dissector.dissect_http(segment.payload)
            result.protocol = "HTTP"
            if http_msg.is_request:
                result.info = f"HTTP {http_msg.method} {http_msg.path}"
            else:
                result.info = f"HTTP {http_msg.status_code}"
        except DissectionError:
            pass  # keep the TCP-level summary
    elif label:
        result.info += f" [{label}]"


def _dissect_udp_layer(payload: bytes, result: DissectedPacket, preview_bytes: int) -> None:
    try:
        segment = udp_dissector.dissect_udp(payload)
    except DissectionError as exc:
        result.parse_error = f"udp: {exc}"
        result.info += " (malformed UDP header)"
        return

    result.src_port = segment.src_port
    result.dst_port = segment.dst_port
    result.payload_preview = _preview(segment.payload, preview_bytes)
    result.info = f"{result.src_ip}:{segment.src_port} -> {result.dst_ip}:{segment.dst_port}"

    if DNS_PORT in (segment.src_port, segment.dst_port):
        try:
            dns_msg = dns_dissector.dissect_dns(segment.payload)
            result.protocol = "DNS"
            direction = "response" if dns_msg.is_response else "query"
            names = ", ".join(q.name for q in dns_msg.questions) or "(no question)"
            result.info = f"DNS {direction}: {names}"
        except DissectionError as exc:
            result.parse_error = f"dns: {exc}"
