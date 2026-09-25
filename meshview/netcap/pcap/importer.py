"""
Import a .pcap file into a CaptureSession.

This is the "file" half of the pipeline described in spec section 5:
it turns raw pcap records into the exact same `DissectedPacket`
objects that live capture (Phase 4) will produce, then writes them to
the DB in batches and maintains the Host/Conversation aggregate
tables so the 3D scene never has to scan the full Packet table.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone as django_timezone

from netcap.dissectors.pipeline import DissectedPacket, dissect_packet
from netcap.models import CaptureSession, Conversation, Host, Packet
from netcap.pcap.reader import PcapFormatError, PcapReader
from django.conf import settings


def _is_private_ip(ip: str) -> bool:
    """Heuristic for spec section 8's "your own machine is highlighted
    at the center": RFC 1918 / loopback / link-local addresses are
    almost always the capturing machine itself or its LAN, never a
    public server it's talking to."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


@dataclass
class ImportStats:
    packet_count: int = 0
    parse_error_count: int = 0
    byte_count: int = 0


class _AggregateTracker:
    """Accumulates Host/Conversation totals in memory during an import,
    then upserts them in one pass at the end -- far cheaper than a DB
    round trip per packet."""

    def __init__(self, session: CaptureSession):
        self.session = session
        self.hosts: dict[str, dict] = {}
        self.conversations: dict[tuple[str, str, str], dict] = {}

    def observe(self, dp: DissectedPacket) -> None:
        for ip in (dp.src_ip, dp.dst_ip):
            if not ip:
                continue
            entry = self.hosts.setdefault(
                ip,
                {
                    "packet_count": 0,
                    "byte_count": 0,
                    "first_seen": dp.timestamp,
                    "last_seen": dp.timestamp,
                    "is_local": _is_private_ip(ip),
                },
            )
            entry["packet_count"] += 1
            entry["byte_count"] += dp.length
            entry["first_seen"] = min(entry["first_seen"], dp.timestamp)
            entry["last_seen"] = max(entry["last_seen"], dp.timestamp)

        if dp.src_ip and dp.dst_ip:
            key = (dp.src_ip, dp.dst_ip, dp.protocol)
            entry = self.conversations.setdefault(
                key,
                {
                    "packet_count": 0,
                    "byte_count": 0,
                    "first_seen": dp.timestamp,
                    "last_seen": dp.timestamp,
                    "encrypted": False,
                },
            )
            entry["packet_count"] += 1
            entry["byte_count"] += dp.length
            entry["first_seen"] = min(entry["first_seen"], dp.timestamp)
            entry["last_seen"] = max(entry["last_seen"], dp.timestamp)
            entry["encrypted"] = entry["encrypted"] or dp.encrypted

    @transaction.atomic
    def flush(self) -> None:
        for ip, data in self.hosts.items():
            host, created = Host.objects.get_or_create(
                session=self.session,
                ip_address=ip,
                defaults={**data},
            )
            if not created:
                host.packet_count += data["packet_count"]
                host.byte_count += data["byte_count"]
                host.first_seen = min(host.first_seen, data["first_seen"])
                host.last_seen = max(host.last_seen, data["last_seen"])
                host.is_local = host.is_local or data["is_local"]
                host.save()

        for (src, dst, protocol), data in self.conversations.items():
            convo, created = Conversation.objects.get_or_create(
                session=self.session,
                src_ip=src,
                dst_ip=dst,
                protocol=protocol,
                defaults={**data},
            )
            if not created:
                convo.packet_count += data["packet_count"]
                convo.byte_count += data["byte_count"]
                convo.first_seen = min(convo.first_seen, data["first_seen"])
                convo.last_seen = max(convo.last_seen, data["last_seen"])
                convo.encrypted = convo.encrypted or data["encrypted"]
                convo.save()


def _to_packet_row(session: CaptureSession, dp: DissectedPacket) -> Packet:
    return Packet(
        session=session,
        timestamp=dp.timestamp,
        src_mac=dp.src_mac,
        dst_mac=dp.dst_mac,
        ethertype=dp.ethertype,
        src_ip=dp.src_ip,
        dst_ip=dp.dst_ip,
        src_port=dp.src_port,
        dst_port=dp.dst_port,
        protocol=dp.protocol,
        ip_protocol_number=dp.ip_protocol_number,
        length=dp.length,
        encrypted=dp.encrypted,
        info=dp.info[:255],
        payload_preview=dp.payload_preview,
    )


def import_pcap_file(
    file_path: str,
    session_name: str | None = None,
    batch_size: int | None = None,
) -> tuple[CaptureSession, ImportStats]:
    """Parse `file_path` and load it into a new CaptureSession.

    Raises PcapFormatError if the file isn't a classic pcap file.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)

    batch_size = batch_size or getattr(settings, "MESHVIEW_BATCH_SIZE", 500)
    preview_bytes = getattr(settings, "MESHVIEW_PAYLOAD_PREVIEW_BYTES", 64)
    session_name = session_name or os.path.basename(file_path)

    session = CaptureSession.objects.create(
        name=session_name,
        source=CaptureSession.Source.FILE,
        original_filename=os.path.basename(file_path),
        started_at=django_timezone.now(),
    )

    stats = ImportStats()
    tracker = _AggregateTracker(session)
    batch: list[Packet] = []
    earliest = latest = None

    with open(file_path, "rb") as stream:
        try:
            reader = PcapReader(stream)
        except PcapFormatError:
            session.delete()
            raise

        for record in reader:
            dp = dissect_packet(record.data, record.timestamp, preview_bytes)
            stats.packet_count += 1
            stats.byte_count += dp.length
            if dp.parse_error:
                stats.parse_error_count += 1

            tracker.observe(dp)
            batch.append(_to_packet_row(session, dp))

            earliest = dp.timestamp if earliest is None else min(earliest, dp.timestamp)
            latest = dp.timestamp if latest is None else max(latest, dp.timestamp)

            if len(batch) >= batch_size:
                Packet.objects.bulk_create(batch)
                batch.clear()

    if batch:
        Packet.objects.bulk_create(batch)

    tracker.flush()

    session.started_at = earliest or session.started_at
    session.ended_at = latest
    session.is_active = False
    session.save()

    return session, stats
