"""
The scene's view of a session: its hosts + conversations right now.

Used by SceneConsumer to feed the browser over a WebSocket. It reads the
database directly, which is what makes live updates work across
processes: `capture_live` (one process) writes the rolling window to
SQLite, the web server (another process) reads it back out. See
consumers.py for why an in-memory channel layer can't do that job.
"""

from __future__ import annotations

from .models import CaptureSession
from .serializers import ConversationSerializer, HostSerializer


def build_scene_snapshot(session_id: int) -> dict | None:
    """Returns None if the session doesn't exist."""
    session = CaptureSession.objects.filter(pk=session_id).first()
    if session is None:
        return None

    # Explicit, total ordering so an unchanged window serialises
    # identically twice in a row (the consumer detects changes by
    # comparing the encoded payloads).
    hosts = session.hosts.order_by("-byte_count", "id")
    conversations = session.conversations.order_by("-byte_count", "id")

    return {
        "session_id": session.id,
        "is_active": session.is_active,
        "hosts": HostSerializer(hosts, many=True).data,
        "conversations": ConversationSerializer(conversations, many=True).data,
    }
