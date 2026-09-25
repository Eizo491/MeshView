"""Build sample.pcap: one DNS query/response pair and one HTTP request,
entirely with struct, so Phase 1 can be tested without a real capture."""
import os
import struct
import time

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.pcap")


def eth(dst, src, ethertype, payload):
    return bytes.fromhex(dst.replace(":", "")) + bytes.fromhex(src.replace(":", "")) + struct.pack("!H", ethertype) + payload


def ipv4(src, dst, proto, payload):
    ver_ihl = (4 << 4) | 5
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, total_len, 0, 0, 64, proto, 0,
        __import__("socket").inet_aton(src), __import__("socket").inet_aton(dst),
    )
    return header + payload


def udp(sport, dport, payload):
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def tcp(sport, dport, flags, payload):
    return struct.pack("!HHIIHHHH", sport, dport, 1000, 0, (5 << 12) | flags, 65535, 0, 0) + payload


def dns_query(name="example.com"):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return header + question


def http_get():
    return b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Meshview/0.1\r\n\r\n"


def write_pcap(frames):
    with open(OUT, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        ts = time.time()
        for frame in frames:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
            ts += 0.1


frames = [
    eth("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", 0x0800,
        ipv4("192.168.1.10", "8.8.8.8", 17, udp(51000, 53, dns_query()))),
    eth("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", 0x0800,
        ipv4("192.168.1.10", "93.184.216.34", 6, tcp(52000, 80, 0x02, b""))),  # SYN
    eth("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", 0x0800,
        ipv4("192.168.1.10", "93.184.216.34", 6, tcp(52000, 80, 0x18, http_get()))),  # PSH+ACK w/ HTTP
]

write_pcap(frames)
print(f"wrote {OUT}")
