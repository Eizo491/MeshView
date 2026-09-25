"""
One WebSocket consumer instance per browser tab watching a session's 3D
scene at ws://<host>/ws/scene/<session_id>/. Read-only: it never reads
anything from the client.

How updates reach the browser
-----------------------------
On connect it sends the session's current hosts/conversations, then
re-reads them every `poll_interval` seconds and sends again only when
something changed. It stops on its own once the session is no longer
active (the last message it sends carries `is_active: false`).

Why it watches the database instead of listening on a Channels group:
`capture_live` and the web server are two separate OS processes, and
Channels' in-memory layer only exists inside one process -- a
`group_send` from the capture process never reaches a socket held by
the server process. (The first version of this file did exactly that;
its tests passed only because they ran both halves in one process.)
The alternatives were channels_redis (needs a Redis server, awkward on
Windows) or an HTTP hop from the capture process to the server. The DB
is already the shared source of truth between the two, SQLite's WAL
mode lets this reader run alongside the capture writer, and the poll
interval matches the engine's 0.5s flush, so nothing is added to the
worst-case latency that isn't already there.
"""

import asyncio
import json
import logging

from asgiref.sync import ThreadSensitiveContext
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer

from .snapshot import build_scene_snapshot

logger = logging.getLogger(__name__)

# Close code for "no such session" (4000-4999 is the application range).
CLOSE_NO_SUCH_SESSION = 4404

# Substrings of asgiref RuntimeErrors that mean the (process-wide) thread-
# sensitive executor is gone -- either the server is shutting down, or two
# thread_sensitive calls collided on the single shared worker thread that
# database_sync_to_async normally funnels through (a known asgiref/Daphne
# rough edge: https://github.com/django/asgiref/issues/348). Neither is
# transient, so retrying every poll_interval just floods the log forever.
_FATAL_EXECUTOR_ERRORS = (
    "would deadlock",
    "after shutdown",
    "after interpreter shutdown",
)


class SceneConsumer(AsyncWebsocketConsumer):
    poll_interval = 0.5  # seconds; matches LiveCaptureEngine.flush_interval

    async def connect(self):
        self.session_id = int(self.scope["url_route"]["kwargs"]["session_id"])
        self._watcher = None

        # Give this connection its own thread-sensitive executor instead of
        # sharing asgiref's single process-wide one. Without this, every
        # database_sync_to_async call from every consumer/request funnels
        # through one shared worker thread, which is what leads to
        # "Single thread executor already being used, would deadlock".
        self._thread_context = ThreadSensitiveContext()
        self._thread_context_closed = False
        await self._thread_context.__aenter__()

        try:
            snapshot = await self._read()
        except Exception:
            await self._exit_thread_context()
            raise

        if snapshot is None:
            await self._exit_thread_context()
            await self.close(code=CLOSE_NO_SUCH_SESSION)
            return

        await self.accept()
        encoded = self._encode(snapshot)
        await self.send(text_data=encoded)

        if snapshot["is_active"]:
            self._watcher = asyncio.ensure_future(self._watch(encoded))

    async def disconnect(self, close_code):
        watcher = getattr(self, "_watcher", None)
        if watcher is not None:
            watcher.cancel()

        await self._exit_thread_context()

    async def _exit_thread_context(self) -> None:
        """Exit ``self._thread_context`` exactly once.

        Channels calls disconnect() even for a connection this consumer
        rejected pre-accept (see the CLOSE_NO_SUCH_SESSION branch in
        connect()), so without this guard the same ThreadSensitiveContext
        gets exited twice -- and asgiref rejects that, since the
        contextvars Token it resets can only be used once
        ("Token has already been used once").
        """
        if getattr(self, "_thread_context_closed", True):
            return
        self._thread_context_closed = True
        await self._thread_context.__aexit__(None, None, None)

    async def _watch(self, last_sent: str) -> None:
        while True:
            await asyncio.sleep(self.poll_interval)
            try:
                snapshot = await self._read()
                if snapshot is None:  # session deleted while we were watching
                    await self.close(code=CLOSE_NO_SUCH_SESSION)
                    return
                encoded = self._encode(snapshot)
                if encoded != last_sent:
                    await self.send(text_data=encoded)
                    last_sent = encoded
                if not snapshot["is_active"]:
                    return  # capture ended; nothing further will change
            except asyncio.CancelledError:
                raise
            except RuntimeError as exc:
                if any(marker in str(exc) for marker in _FATAL_EXECUTOR_ERRORS):
                    logger.warning(
                        "scene watcher for session %s stopping: %s",
                        self.session_id,
                        exc,
                    )
                    return  # not recoverable -- stop instead of spamming retries
                logger.exception("scene watcher for session %s failed; retrying", self.session_id)
            except Exception:  # noqa: BLE001 - a transient DB hiccup shouldn't end the feed
                logger.exception("scene watcher for session %s failed; retrying", self.session_id)

    @database_sync_to_async
    def _read(self):
        return build_scene_snapshot(self.session_id)

    @staticmethod
    def _encode(snapshot: dict) -> str:
        return json.dumps(snapshot, sort_keys=True)
