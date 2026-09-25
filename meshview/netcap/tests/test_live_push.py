"""
SceneConsumer: what a browser tab sees over ws://.../ws/scene/<id>/.

These run in one process with Channels' WebsocketCommunicator, which is
fine *now* because the consumer no longer depends on an in-memory
channel layer -- it reads the database. The part these tests can't
prove is that it works while a *different process* is writing that
database (the real `capture_live` + web server setup). That is checked
end-to-end by a separate script, described in the README's Phase 4
notes, and not by this suite.
"""

from asgiref.sync import sync_to_async
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.test import TransactionTestCase
from django.utils import timezone as django_timezone

from netcap.consumers import CLOSE_NO_SUCH_SESSION, SceneConsumer
from netcap.models import CaptureSession, Conversation, Host
from netcap.routing import websocket_urlpatterns


def make_session(is_active=True, name="live"):
    return CaptureSession.objects.create(
        name=name, source=CaptureSession.Source.LIVE,
        started_at=django_timezone.now(), is_active=is_active,
    )


def add_host(session, ip, is_local=False, packets=3, size=300):
    now = django_timezone.now()
    return Host.objects.create(
        session=session, ip_address=ip, is_local=is_local,
        packet_count=packets, byte_count=size, first_seen=now, last_seen=now,
    )


def add_conversation(session, src, dst, protocol="DNS", packets=3, size=300):
    now = django_timezone.now()
    return Conversation.objects.create(
        session=session, src_ip=src, dst_ip=dst, protocol=protocol,
        packet_count=packets, byte_count=size, first_seen=now, last_seen=now,
    )


class SceneConsumerTests(TransactionTestCase):
    def setUp(self):
        # Poll fast so tests don't sit around for half a second per update.
        self._orig_interval = SceneConsumer.poll_interval
        SceneConsumer.poll_interval = 0.05

    def tearDown(self):
        SceneConsumer.poll_interval = self._orig_interval

    def _communicator(self, session_id):
        return WebsocketCommunicator(
            URLRouter(websocket_urlpatterns), f"/ws/scene/{session_id}/"
        )

    async def test_sends_current_state_immediately_on_connect(self):
        def build():
            s = make_session()
            add_host(s, "192.168.1.10", is_local=True)
            add_host(s, "8.8.8.8")
            add_conversation(s, "192.168.1.10", "8.8.8.8")
            return s

        session = await sync_to_async(build)()
        comm = self._communicator(session.id)
        connected, _ = await comm.connect()
        self.assertTrue(connected)

        msg = await comm.receive_json_from()
        self.assertEqual(msg["session_id"], session.id)
        self.assertTrue(msg["is_active"])
        self.assertEqual({h["ip_address"] for h in msg["hosts"]}, {"192.168.1.10", "8.8.8.8"})
        self.assertEqual(len(msg["conversations"]), 1)
        await comm.disconnect()

    async def test_pushes_an_update_when_the_database_changes(self):
        session = await sync_to_async(make_session)()
        await sync_to_async(add_host)(session, "192.168.1.10", True)

        comm = self._communicator(session.id)
        await comm.connect()
        first = await comm.receive_json_from()
        self.assertEqual(len(first["hosts"]), 1)

        # What the capture process does on a flush, from outside the socket.
        await sync_to_async(add_host)(session, "1.1.1.1")
        await sync_to_async(add_conversation)(session, "192.168.1.10", "1.1.1.1", "HTTPS")

        second = await comm.receive_json_from(timeout=2)
        self.assertEqual({h["ip_address"] for h in second["hosts"]}, {"192.168.1.10", "1.1.1.1"})
        self.assertEqual(second["conversations"][0]["protocol"], "HTTPS")
        await comm.disconnect()

    async def test_removals_are_pushed_too(self):
        # The rolling window forgets hosts; the scene has to be told.
        session = await sync_to_async(make_session)()
        await sync_to_async(add_host)(session, "192.168.1.10", True)
        gone = await sync_to_async(add_host)(session, "9.9.9.9")

        comm = self._communicator(session.id)
        await comm.connect()
        first = await comm.receive_json_from()
        self.assertEqual(len(first["hosts"]), 2)

        await sync_to_async(gone.delete)()
        second = await comm.receive_json_from(timeout=2)
        self.assertEqual([h["ip_address"] for h in second["hosts"]], ["192.168.1.10"])
        await comm.disconnect()

    async def test_unchanged_state_is_not_resent(self):
        session = await sync_to_async(make_session)()
        await sync_to_async(add_host)(session, "192.168.1.10", True)

        comm = self._communicator(session.id)
        await comm.connect()
        await comm.receive_json_from()  # initial snapshot

        self.assertTrue(await comm.receive_nothing(timeout=0.3))
        await comm.disconnect()

    async def test_client_only_receives_its_own_session(self):
        watched = await sync_to_async(make_session)(name="watched")
        other = await sync_to_async(make_session)(name="other")

        comm = self._communicator(watched.id)
        await comm.connect()
        await comm.receive_json_from()

        await sync_to_async(add_host)(other, "7.7.7.7")
        self.assertTrue(await comm.receive_nothing(timeout=0.3))
        await comm.disconnect()

    async def test_ended_session_reports_inactive_then_stops_watching(self):
        session = await sync_to_async(make_session)()
        await sync_to_async(add_host)(session, "192.168.1.10", True)

        comm = self._communicator(session.id)
        await comm.connect()
        first = await comm.receive_json_from()
        self.assertTrue(first["is_active"])

        def end():
            session.is_active = False
            session.save()

        await sync_to_async(end)()
        final = await comm.receive_json_from(timeout=2)
        self.assertFalse(final["is_active"])

        # Watcher has stopped: later DB changes are no longer sent.
        await sync_to_async(add_host)(session, "5.5.5.5")
        self.assertTrue(await comm.receive_nothing(timeout=0.3))
        await comm.disconnect()

    async def test_connecting_to_an_already_ended_session_sends_once_and_goes_quiet(self):
        session = await sync_to_async(make_session)(is_active=False)
        await sync_to_async(add_host)(session, "192.168.1.10", True)

        comm = self._communicator(session.id)
        await comm.connect()
        msg = await comm.receive_json_from()
        self.assertFalse(msg["is_active"])
        self.assertTrue(await comm.receive_nothing(timeout=0.3))
        await comm.disconnect()

    async def test_unknown_session_is_rejected(self):
        comm = self._communicator(999999)
        connected, code = await comm.connect()
        self.assertFalse(connected)
        self.assertEqual(code, CLOSE_NO_SUCH_SESSION)
