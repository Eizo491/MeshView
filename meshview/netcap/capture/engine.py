"""
Phase 4's live-capture engine.

This is deliberately the *only* place Phase 4's logic lives that isn't
either (a) the one-line call into the shared `dissect_packet` pipeline
or (b) OS-level packet sniffing. `capture_live` (the management
command) knows how to get raw frames out of Npcap via scapy and
nothing else -- it hands each frame to `LiveCaptureEngine.handle_frame()`
and this file does the rest: batching, the rolling ~60s window, and
notifying a caller after each flush so it can push the update onward
(over a WebSocket, in production).

Why this split matters here specifically: this sandbox has no NIC and
can't install Npcap, so the actual sniffing can never be exercised in
this environment -- only on your machine, as admin. Keeping this class
free of any scapy/OS dependency means the rolling-window logic (the
part most likely to have off-by-one/timing bugs) *can* be fully
unit-tested here with synthetic frames, same as Phase 1's dissectors
were. See netcap/tests/test_capture_engine.py.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Callable, Optional

from django.conf import settings
from django.db import transaction
from django.utils import timezone as django_timezone

from netcap.dissectors.pipeline import DissectedPacket, dissect_packet
from netcap.models import CaptureSession, Conversation, Host, Packet
from netcap.pcap.importer import _is_private_ip, _to_packet_row


@dataclass
class LiveCaptureStats:
    packet_count: int = 0
    byte_count: int = 0
    parse_error_count: int = 0


class LiveCaptureEngine:
    """Feed raw Ethernet frames in with `handle_frame()`.

    - Every frame goes through the exact same `dissect_packet` the PCAP
      importer uses (spec section 5 -- one pipeline, two sources).
    - Decoded packets are buffered and `bulk_create`d on a time-based
      flush (every `flush_interval` seconds) as well as a size
      threshold, so a quiet capture still updates promptly rather than
      waiting for `batch_size` packets that might never come.
    - Each flush deletes this session's `Packet` rows older than
      `window_seconds` (default 60) and fully recomputes Host/
      Conversation from whatever's left -- unlike the PCAP importer's
      tracker, which accumulates totals for the whole file, a live
      session's scene should *forget* a host or conversation once it
      falls out of the rolling window, per spec section 8. A full
      recompute (rather than incremental add/subtract as rows expire)
      is simpler and can't drift out of sync with what just got
      deleted; it's cheap enough at the "tens to low hundreds of
      hosts" scale Phase 3's force layout already assumes.
    - `on_flush(session, stats)` fires after every flush (including
      empty ones driven by `tick()`) so a caller can push the new
      hosts/conversations onward without this class knowing anything
      about Channels/WebSockets.
    """

    def __init__(
        self,
        session: CaptureSession,
        window_seconds: int = 60,
        flush_interval: float = 0.5,
        batch_size: int | None = None,
        payload_preview_bytes: int | None = None,
        on_flush: Optional[Callable[[CaptureSession, LiveCaptureStats], None]] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.session = session
        self.window_seconds = window_seconds
        self.flush_interval = flush_interval
        self.batch_size = batch_size or getattr(settings, "MESHVIEW_BATCH_SIZE", 500)
        self.preview_bytes = payload_preview_bytes or getattr(
            settings, "MESHVIEW_PAYLOAD_PREVIEW_BYTES", 64
        )
        self.on_flush = on_flush
        self._clock = clock

        self.stats = LiveCaptureStats()
        self._batch: list[Packet] = []
        self._last_flush = self._clock()

    def handle_frame(self, raw: bytes, timestamp: datetime) -> DissectedPacket:
        """Dissect one frame, buffer it, and flush if a threshold is due."""
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=dt_timezone.utc)

        dp = dissect_packet(raw, timestamp, self.preview_bytes)
        self.stats.packet_count += 1
        self.stats.byte_count += dp.length
        if dp.parse_error:
            self.stats.parse_error_count += 1

        self._batch.append(_to_packet_row(self.session, dp))

        if len(self._batch) >= self.batch_size or self._due_for_time_flush():
            self.flush()

        return dp

    def tick(self) -> None:
        """Call periodically from an idle capture loop. A lull in
        traffic should still flush on the time interval and still
        prune the rolling window -- otherwise a session that goes
        quiet keeps showing hosts/conversations that are actually long
        gone from the window. Only flushes if the interval has actually
        elapsed -- callers driving this from a tighter loop than
        `flush_interval` shouldn't cause more-than-intended flushes."""
        if self._due_for_time_flush():
            self.flush()

    def _due_for_time_flush(self) -> bool:
        return (self._clock() - self._last_flush) >= self.flush_interval

    @transaction.atomic
    def flush(self) -> None:
        if self._batch:
            Packet.objects.bulk_create(self._batch)
            self._batch.clear()

        cutoff = django_timezone.now() - timedelta(seconds=self.window_seconds)
        Packet.objects.filter(session=self.session, timestamp__lt=cutoff).delete()
        self._recompute_aggregates(cutoff)

        self._last_flush = self._clock()
        if self.on_flush:
            self.on_flush(self.session, self.stats)

    def _recompute_aggregates(self, cutoff: datetime) -> None:
        window = Packet.objects.filter(session=self.session, timestamp__gte=cutoff)

        hosts: dict[str, dict] = {}
        conversations: dict[tuple[str, str, str], dict] = {}

        for p in window.iterator():
            for ip in (p.src_ip, p.dst_ip):
                if not ip:
                    continue
                entry = hosts.setdefault(
                    ip,
                    {
                        "packet_count": 0,
                        "byte_count": 0,
                        "first_seen": p.timestamp,
                        "last_seen": p.timestamp,
                        "is_local": _is_private_ip(ip),
                    },
                )
                entry["packet_count"] += 1
                entry["byte_count"] += p.length
                entry["first_seen"] = min(entry["first_seen"], p.timestamp)
                entry["last_seen"] = max(entry["last_seen"], p.timestamp)

            if p.src_ip and p.dst_ip:
                key = (p.src_ip, p.dst_ip, p.protocol)
                entry = conversations.setdefault(
                    key,
                    {
                        "packet_count": 0,
                        "byte_count": 0,
                        "first_seen": p.timestamp,
                        "last_seen": p.timestamp,
                        "encrypted": False,
                    },
                )
                entry["packet_count"] += 1
                entry["byte_count"] += p.length
                entry["first_seen"] = min(entry["first_seen"], p.timestamp)
                entry["last_seen"] = max(entry["last_seen"], p.timestamp)
                entry["encrypted"] = entry["encrypted"] or p.encrypted

        self._sync_hosts(hosts)
        self._sync_conversations(conversations)

    def _sync_hosts(self, hosts: dict[str, dict]) -> None:
        existing = {h.ip_address: h for h in self.session.hosts.all()}

        for ip, data in hosts.items():
            host = existing.get(ip)
            if host is None:
                Host.objects.create(session=self.session, ip_address=ip, **data)
            else:
                for field, value in data.items():
                    setattr(host, field, value)
                host.save()

        stale = set(existing) - set(hosts)
        if stale:
            Host.objects.filter(session=self.session, ip_address__in=stale).delete()

    def _sync_conversations(self, conversations: dict[tuple[str, str, str], dict]) -> None:
        existing = {
            (c.src_ip, c.dst_ip, c.protocol): c for c in self.session.conversations.all()
        }

        for (src, dst, protocol), data in conversations.items():
            convo = existing.get((src, dst, protocol))
            if convo is None:
                Conversation.objects.create(
                    session=self.session, src_ip=src, dst_ip=dst, protocol=protocol, **data
                )
            else:
                for field, value in data.items():
                    setattr(convo, field, value)
                convo.save()

        stale = set(existing) - set(conversations)
        for key in stale:
            existing[key].delete()
