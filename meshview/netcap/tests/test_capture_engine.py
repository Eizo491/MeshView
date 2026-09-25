"""
Tests for LiveCaptureEngine -- the part of Phase 4 that doesn't need
Npcap, a NIC, or scapy, and so is the part that actually *can* be
verified in this environment. `capture_live` (the management command
that wraps scapy.sniff) is intentionally thin specifically so this is
true: everything but the OS-level sniff call is covered here.

A fake monotonic clock stands in for time.monotonic() so flush timing
is deterministic instead of racing the test runner.
"""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone as django_timezone

from netcap.capture.engine import LiveCaptureEngine
from netcap.models import CaptureSession, Conversation, Host, Packet
from netcap.tests.frames import dns_frame, tcp_syn_frame


class FakeClock:
    """A controllable stand-in for time.monotonic()."""

    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds: float):
        self.now += seconds


def make_session(**kwargs):
    defaults = dict(
        name="test live session",
        source=CaptureSession.Source.LIVE,
        started_at=django_timezone.now(),
        is_active=True,
    )
    defaults.update(kwargs)
    return CaptureSession.objects.create(**defaults)


class BatchingTests(TestCase):
    def test_flushes_on_batch_size(self):
        session = make_session()
        clock = FakeClock()
        engine = LiveCaptureEngine(session, batch_size=3, flush_interval=1000, clock=clock)

        for _ in range(2):
            engine.handle_frame(dns_frame(), django_timezone.now())
        self.assertEqual(Packet.objects.filter(session=session).count(), 0)  # not flushed yet

        engine.handle_frame(dns_frame(), django_timezone.now())  # 3rd frame hits batch_size
        self.assertEqual(Packet.objects.filter(session=session).count(), 3)

    def test_flushes_on_time_interval_even_below_batch_size(self):
        session = make_session()
        clock = FakeClock()
        engine = LiveCaptureEngine(session, batch_size=500, flush_interval=0.5, clock=clock)

        engine.handle_frame(dns_frame(), django_timezone.now())
        self.assertEqual(Packet.objects.filter(session=session).count(), 0)

        clock.advance(0.6)
        engine.handle_frame(tcp_syn_frame(), django_timezone.now())
        # The time check happens after appending, so both frames land together.
        self.assertEqual(Packet.objects.filter(session=session).count(), 2)

    def test_tick_flushes_idle_batch_without_new_frames(self):
        session = make_session()
        clock = FakeClock()
        engine = LiveCaptureEngine(session, batch_size=500, flush_interval=0.5, clock=clock)
        engine.handle_frame(dns_frame(), django_timezone.now())

        clock.advance(0.1)
        engine.tick()
        self.assertEqual(Packet.objects.filter(session=session).count(), 0)  # not due yet

        clock.advance(0.5)
        engine.tick()
        self.assertEqual(Packet.objects.filter(session=session).count(), 1)

    def test_on_flush_callback_fires(self):
        session = make_session()
        seen = []
        engine = LiveCaptureEngine(
            session, batch_size=1, flush_interval=1000,
            on_flush=lambda s, stats: seen.append((s.id, stats.packet_count)),
        )
        engine.handle_frame(dns_frame(), django_timezone.now())
        self.assertEqual(seen, [(session.id, 1)])


class RollingWindowTests(TestCase):
    def test_old_packets_are_pruned_on_flush(self):
        session = make_session()
        engine = LiveCaptureEngine(session, window_seconds=60, batch_size=1)

        old_ts = django_timezone.now() - timedelta(seconds=90)
        recent_ts = django_timezone.now()

        engine.handle_frame(dns_frame(), old_ts)
        engine.handle_frame(tcp_syn_frame(), recent_ts)

        packets = Packet.objects.filter(session=session)
        self.assertEqual(packets.count(), 1)
        self.assertEqual(packets.first().protocol, "TCP")

    def test_hosts_and_conversations_drop_out_when_they_leave_the_window(self):
        session = make_session()
        engine = LiveCaptureEngine(session, window_seconds=60, batch_size=1)

        # A host/conversation that will fall out of the window...
        engine.handle_frame(dns_frame(src="192.168.1.50"), django_timezone.now())
        self.assertTrue(Host.objects.filter(session=session, ip_address="192.168.1.50").exists())
        self.assertTrue(Conversation.objects.filter(session=session, src_ip="192.168.1.50").exists())

        # ...gets pushed out once a later flush's cutoff is past its timestamp.
        Packet.objects.filter(session=session).update(
            timestamp=django_timezone.now() - timedelta(seconds=61)
        )
        engine.handle_frame(tcp_syn_frame(src="192.168.1.60"), django_timezone.now())

        self.assertFalse(Host.objects.filter(session=session, ip_address="192.168.1.50").exists())
        self.assertFalse(Conversation.objects.filter(session=session, src_ip="192.168.1.50").exists())
        self.assertTrue(Host.objects.filter(session=session, ip_address="192.168.1.60").exists())

    def test_aggregate_counts_reflect_only_the_window(self):
        session = make_session()
        engine = LiveCaptureEngine(session, window_seconds=60, batch_size=1)

        for _ in range(3):
            engine.handle_frame(dns_frame(), django_timezone.now())

        convo = Conversation.objects.get(session=session, src_ip="192.168.1.10", dst_ip="8.8.8.8")
        self.assertEqual(convo.packet_count, 3)

        host = Host.objects.get(session=session, ip_address="192.168.1.10")
        self.assertEqual(host.packet_count, 3)
        self.assertTrue(host.is_local)  # 192.168.0.0/16 is RFC1918


class SamePipelineAsImporterTests(TestCase):
    """Confirms Phase 4 really does reuse Phase 1's pipeline end to end,
    not a reimplementation that happens to look similar."""

    def test_decoded_fields_match_direct_pipeline_call(self):
        from netcap.dissectors.pipeline import dissect_packet

        session = make_session()
        engine = LiveCaptureEngine(session, batch_size=1)
        raw = dns_frame()
        ts = django_timezone.now()

        dp = engine.handle_frame(raw, ts)
        direct = dissect_packet(raw, ts)

        self.assertEqual(dp.protocol, direct.protocol)
        self.assertEqual(dp.info, direct.info)
        self.assertEqual(dp.src_ip, direct.src_ip)
        self.assertEqual(dp.dst_ip, direct.dst_ip)
