"""Synthetic Ethernet frame builders for tests, built with struct only
-- the same approach sample_pcaps/make_sample.py uses for Phase 1, so
live-capture tests don't need a real NIC, Npcap, or scapy to exercise
the dissector pipeline and the capture engine built on top of it."""

import socket
import struct


def eth(dst_mac: str, src_mac: str, ethertype: int, payload: bytes) -> bytes:
    return (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + struct.pack("!H", ethertype)
        + payload
    )


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    ver_ihl = (4 << 4) | 5
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, 0, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return header + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes) -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, 1000, 0, (5 << 12) | flags, 65535, 0, 0) + payload


def dns_query(name: str = "example.com") -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def dns_frame(src="192.168.1.10", dst="8.8.8.8", sport=51000, name="example.com") -> bytes:
    return eth(
        "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", 0x0800,
        ipv4(src, dst, 17, udp(sport, 53, dns_query(name))),
    )


def tcp_syn_frame(src="192.168.1.10", dst="93.184.216.34", sport=52000, dport=80) -> bytes:
    return eth(
        "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", 0x0800,
        ipv4(src, dst, 6, tcp(sport, dport, 0x02, b"")),
    )
