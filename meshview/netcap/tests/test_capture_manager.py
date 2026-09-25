"""
Tests for `netcap.capture.manager` -- the "Start Capture" button's
backend. Like `capture_live.py`, the actual OS-level sniffing can't be
exercised in this sandbox (no NIC, no Npcap), so these tests replace
`_require_scapy()` with a fake `sniff()` that plays back synthetic
frames and blocks on the same `stop_filter` contract the real
scapy.sniff() honors. Everything downstream of that -- session
creation, threading, start/stop/status, error propagation -- is real.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest import mock

from django.test import TransactionTestCase

from netcap.capture import manager as manager_module
from netcap.capture.manager import (
    CaptureAlreadyRunning,
    CaptureError,
    CaptureManager,
    CaptureNotRunning,
)
from netcap.models import CaptureSession, Packet
from netcap.tests.frames import dns_frame


class FakePacket:
    """Stands in for a scapy packet: bytes(pkt) and pkt.time."""

    def __init__(self, raw: bytes, ts: float):
        self._raw = raw
        self.time = ts

    def __bytes__(self):
        return self._raw


def make_fake_sniff(frame_interval=0.01, on_iteration=None):
    """A fake scapy.sniff(): feeds one dns_frame() per loop, waiting on
    `stop_filter` between frames instead of a real interface, so tests
    control exactly when it returns."""

    def fake_sniff(iface, filter, prn, store, stop_filter):
        while not stop_filter(None):
            if on_iteration:
                on_iteration()
            prn(FakePacket(dns_frame(), time.time()))
            time.sleep(frame_interval)

    return fake_sniff


def patch_scapy(fake_sniff=None, raise_import_error=False):
    if raise_import_error:
        return mock.patch.object(
            manager_module, "_require_scapy", side_effect=CaptureError("scapy is not installed")
        )
    fake_conf = SimpleNamespace(ifaces=SimpleNamespace(values=lambda: []))
    return mock.patch.object(
        manager_module, "_require_scapy", return_value=(fake_conf, fake_sniff or make_fake_sniff())
    )


class CaptureManagerLifecycleTests(TransactionTestCase):
    # TransactionTestCase, not TestCase: the manager writes from a real
    # background thread (its own DB connection), while a plain TestCase
    # wraps the test body in an open transaction on the main thread's
    # connection -- on SQLite that's a recipe for "database table is
    # locked" the moment the background thread tries to bulk_create.
    def setUp(self):
        self.mgr = CaptureManager()
        # Belt-and-suspenders: if a test fails/errors partway through with
        # a capture still running, its background thread must not survive
        # into the next test -- on a shared-cache in-memory SQLite DB, an
        # orphaned thread still calling bulk_create() is a "database table
        # is locked" waiting to happen for whichever test runs next.
        self.addCleanup(self._stop_if_running)

    def _stop_if_running(self):
        try:
            self.mgr.stop(timeout=5)
        except CaptureNotRunning:
            pass

    def test_status_when_idle(self):
        self.assertEqual(self.mgr.status(), {"running": False})

    def test_start_creates_active_live_session_and_status_reflects_it(self):
        with patch_scapy():
            session = self.mgr.start(iface="eth0")

        self.assertEqual(session.source, CaptureSession.Source.LIVE)
        self.assertEqual(session.interface, "eth0")
        self.assertTrue(session.is_active)

        status = self.mgr.status()
        self.assertTrue(status["running"])
        self.assertEqual(status["session_id"], session.id)
        self.assertEqual(status["iface"], "eth0")

        self.mgr.stop()

    def test_frames_actually_flow_through_to_packets(self):
        with patch_scapy(make_fake_sniff(frame_interval=0.01)):
            session = self.mgr.start(iface="eth0", window_seconds=60)
            # give the fake sniff loop a few iterations to produce packets
            deadline = time.monotonic() + 2
            while Packet.objects.filter(session=session).count() == 0:
                if time.monotonic() > deadline:
                    self.fail("no packets appeared within timeout")
                time.sleep(0.02)

            result = self.mgr.stop()

        self.assertTrue(result["stopped"])
        self.assertGreater(result["packet_count"], 0)
        session.refresh_from_db()
        self.assertFalse(session.is_active)
        self.assertIsNotNone(session.ended_at)

    def test_cannot_start_twice_concurrently(self):
        with patch_scapy():
            self.mgr.start(iface="eth0")
            with self.assertRaises(CaptureAlreadyRunning):
                self.mgr.start(iface="eth1")
            self.mgr.stop()

    def test_stop_without_a_running_capture_raises(self):
        with self.assertRaises(CaptureNotRunning):
            self.mgr.stop()

    def test_start_without_scapy_raises_capture_error(self):
        with patch_scapy(raise_import_error=True):
            with self.assertRaises(CaptureError):
                self.mgr.start(iface="eth0")
        self.assertEqual(self.mgr.status(), {"running": False})

    def test_start_requires_iface(self):
        with self.assertRaises(CaptureError):
            self.mgr.start(iface="")

    def test_permission_error_surfaces_in_status_and_clears_is_active(self):
        def fake_sniff(iface, filter, prn, store, stop_filter):
            raise PermissionError()

        with patch_scapy(fake_sniff):
            session = self.mgr.start(iface="eth0")

        deadline = time.monotonic() + 2
        status = self.mgr.status()
        while status.get("error") is None and time.monotonic() < deadline:
            time.sleep(0.02)
            status = self.mgr.status()

        self.assertIsNotNone(status.get("error"))
        self.assertIn("Permission denied", status["error"])
        session.refresh_from_db()
        self.assertFalse(session.is_active)

        # A dead-but-not-yet-cleared capture still counts as "running" for
        # concurrency purposes: don't let a second one stomp on the DB
        # rows the failed thread is still tidying up. It should, however,
        # be stoppable to clear the slot.
        with self.assertRaises(CaptureAlreadyRunning):
            self.mgr.start(iface="eth1")

    def test_stop_is_idempotent_after_natural_end(self):
        # A short-lived fake capture that ends on its own (stop_filter
        # never even needs to fire) should leave the manager idle, and a
        # second start() should be free to go.
        def fake_sniff(iface, filter, prn, store, stop_filter):
            prn(FakePacket(dns_frame(), time.time()))
            # returns immediately, as if the interface went away

        with patch_scapy(fake_sniff):
            session = self.mgr.start(iface="eth0")

        deadline = time.monotonic() + 2
        while self.mgr.status()["running"] is not False and time.monotonic() < deadline:
            time.sleep(0.02)

        with patch_scapy(make_fake_sniff()):
            session2 = self.mgr.start(iface="eth1")
        self.assertNotEqual(session.id, session2.id)
        self.mgr.stop()


class CaptureAPITests(TransactionTestCase):
    """The /api/capture/* endpoints, exercised through the manager
    singleton (patched the same way as above)."""

    def tearDown(self):
        # Leave the process-wide singleton clean between tests.
        try:
            manager_module.manager.stop()
        except CaptureNotRunning:
            pass

    def test_start_status_stop_roundtrip(self):
        with patch_scapy(make_fake_sniff()):
            res = self.client.post(
                "/api/capture/start/", {"iface": "eth0"}, content_type="application/json"
            )
            self.assertEqual(res.status_code, 201)
            session_id = res.json()["session"]["id"]

            status_res = self.client.get("/api/capture/status/")
            self.assertTrue(status_res.json()["running"])
            self.assertEqual(status_res.json()["session_id"], session_id)

            stop_res = self.client.post("/api/capture/stop/")
            self.assertEqual(stop_res.status_code, 200)
            self.assertTrue(stop_res.json()["stopped"])

        idle = self.client.get("/api/capture/status/")
        self.assertFalse(idle.json()["running"])

    def test_start_requires_iface_field(self):
        res = self.client.post("/api/capture/start/", {}, content_type="application/json")
        self.assertEqual(res.status_code, 400)

    def test_double_start_is_409(self):
        with patch_scapy(make_fake_sniff()):
            first = self.client.post(
                "/api/capture/start/", {"iface": "eth0"}, content_type="application/json"
            )
            self.assertEqual(first.status_code, 201)
            second = self.client.post(
                "/api/capture/start/", {"iface": "eth1"}, content_type="application/json"
            )
            self.assertEqual(second.status_code, 409)

    def test_stop_with_nothing_running_is_409(self):
        res = self.client.post("/api/capture/stop/")
        self.assertEqual(res.status_code, 409)

    def test_interfaces_endpoint_surfaces_missing_scapy_as_400(self):
        with patch_scapy(raise_import_error=True):
            res = self.client.get("/api/capture/interfaces/")
        self.assertEqual(res.status_code, 400)
