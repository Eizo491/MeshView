"""
A from-scratch reader for the classic libpcap file format (.pcap).

This only parses the *container* -- the global header and per-packet
record headers -- to hand raw frame bytes to the dissector pipeline.
It intentionally does not use scapy or dpkt for this: per the spec,
scapy is reserved for live capture only, and protocol decoding is
custom throughout.

File layout (https://wiki.wireshark.org/Development/LibpcapFileFormat):

Global header (24 bytes)
    magic_number   u32   0xa1b2c3d4 (us) / 0xa1b23c4d (ns) +/- byte swap
    version_major  u16
    version_minor  u16
    thiszone       i32   (ignored; almost always 0)
    sigfigs        u32   (ignored; almost always 0)
    snaplen        u32   max bytes captured per packet
    network        u32   link-layer header type (1 = Ethernet)

Per-packet record, repeated to EOF:
    ts_sec         u32   timestamp, seconds
    ts_usec        u32   timestamp, microseconds (or nanoseconds, see magic)
    incl_len       u32   number of octets of packet saved in file
    orig_len       u32   actual length of packet as it appeared on the wire
    data           bytes[incl_len]

Only pcapng (.pcapng) is out of scope; that's a different, block-based
format. This module raises PcapFormatError for it so callers can give
a clear message instead of misreading the bytes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import BinaryIO, Iterator

_MAGIC_LE_US = 0xA1B2C3D4  # little-endian, microsecond timestamps
_MAGIC_BE_US = 0xD4C3B2A1  # big-endian, microsecond timestamps
_MAGIC_LE_NS = 0xA1B23C4D  # little-endian, nanosecond timestamps
_MAGIC_BE_NS = 0x4D3CB2A1  # big-endian, nanosecond timestamps

_PCAPNG_MAGIC = 0x0A0D0D0A

LINKTYPE_ETHERNET = 1

GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16


class PcapFormatError(ValueError):
    pass


@dataclass
class PcapGlobalHeader:
    byte_order: str  # "<" or ">" for struct format strings
    nanosecond_precision: bool
    version_major: int
    version_minor: int
    snaplen: int
    linktype: int


@dataclass
class PcapRecord:
    timestamp: datetime
    captured_length: int  # bytes actually present (incl_len)
    original_length: int  # bytes on the wire (orig_len)
    data: bytes


def _read_global_header(stream: BinaryIO) -> PcapGlobalHeader:
    raw = stream.read(GLOBAL_HEADER_LEN)
    if len(raw) < GLOBAL_HEADER_LEN:
        raise PcapFormatError("file is too short to contain a pcap global header")

    (magic,) = struct.unpack("<I", raw[0:4])

    if magic == _PCAPNG_MAGIC or struct.unpack(">I", raw[0:4])[0] == _PCAPNG_MAGIC:
        raise PcapFormatError(
            "this looks like a pcapng file, not classic pcap; pcapng is not supported"
        )

    if magic == _MAGIC_LE_US:
        order, ns = "<", False
    elif magic == _MAGIC_BE_US:
        order, ns = ">", False
    elif magic == _MAGIC_LE_NS:
        order, ns = "<", True
    elif magic == _MAGIC_BE_NS:
        order, ns = ">", True
    else:
        raise PcapFormatError(f"unrecognized pcap magic number: 0x{magic:08x}")

    version_major, version_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(
        f"{order}HHiIII", raw[4:24]
    )

    return PcapGlobalHeader(
        byte_order=order,
        nanosecond_precision=ns,
        version_major=version_major,
        version_minor=version_minor,
        snaplen=snaplen,
        linktype=linktype,
    )


class PcapReader:
    """Reads a classic-pcap stream: header available immediately on
    construction, packets streamed one at a time via iteration so an
    importer never has to hold a whole large capture in memory."""

    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.header = _read_global_header(stream)

    def __iter__(self) -> Iterator[PcapRecord]:
        return self

    def __next__(self) -> PcapRecord:
        record_header = self.stream.read(RECORD_HEADER_LEN)
        if len(record_header) == 0:
            raise StopIteration
        if len(record_header) < RECORD_HEADER_LEN:
            raise PcapFormatError("truncated packet record header at end of file")

        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            f"{self.header.byte_order}IIII", record_header
        )

        data = self.stream.read(incl_len)
        if len(data) < incl_len:
            raise PcapFormatError("truncated packet data at end of file")

        divisor = 1_000_000_000 if self.header.nanosecond_precision else 1_000_000
        timestamp = datetime.fromtimestamp(ts_sec, tz=timezone.utc) + timedelta(
            seconds=ts_frac / divisor
        )

        return PcapRecord(
            timestamp=timestamp,
            captured_length=incl_len,
            original_length=orig_len,
            data=data,
        )


def iter_records(stream: BinaryIO) -> Iterator[tuple[PcapGlobalHeader, PcapRecord]]:
    """Yield (header, record) pairs; a thin convenience wrapper around
    PcapReader for callers that want the header alongside each record."""
    reader = PcapReader(stream)
    for record in reader:
        yield reader.header, record


def read_all(path: str) -> tuple[PcapGlobalHeader, list[PcapRecord]]:
    """Convenience wrapper for small files / tests. The importer uses
    `PcapReader` directly so large PCAPs don't have to fit in memory."""
    with open(path, "rb") as stream:
        reader = PcapReader(stream)
        return reader.header, list(reader)
