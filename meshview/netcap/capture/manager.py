"""
Runs a live capture inside the web server process, for the UI's
"Start Capture" control.

Why this is a separate module from `capture_live.py`
------------------------------------------------------
`capture_live.py` is a management command: its own process, its own
SIGINT handling, progress on stdout, gone when you Ctrl+C. That's the
right shape for "run this from a terminal, elevated, leave it
running."

The web UI needs a different shape. A `POST /api/capture/start/`
request comes in on one request-handling thread and has to return
right away; the sniff loop then has to keep running in the
background until a later `POST /api/capture/stop/` (or the process
exits). This module is that: a small, process-wide singleton --
`manager`, below -- that owns at most one running capture, with
start()/stop()/status() instead of a CLI's argv/stdout/SIGINT.

Everything from "raw frame + timestamp" onward is delegated to
`LiveCaptureEngine`, exactly as it is in `capture_live.py` -- this
file only duplicates the sniff-thread wiring, never the capture or
windowing logic. And like `engine.py` and `interfaces.py`, importing
this module never touches scapy: the import happens inside
`start()`, so a server with no Npcap installed still boots fine and
every other page keeps working.

Only one capture runs at a time (matching the CLI: nothing stops you
running `capture_live` twice from two terminals either, but nothing
in this app expects concurrent live sessions).
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from django.utils import timezone as django_timezone

from netcap.capture.engine import LiveCaptureEngine, LiveCaptureStats
from netcap.capture.interfaces import InterfaceRow, collect_interfaces
from netcap.models import CaptureSession


class CaptureError(Exception):
    """Raised for problems starting a capture (bad iface, no scapy, ...)."""


class CaptureAlreadyRunning(CaptureError):
    pass


class CaptureNotRunning(CaptureError):
    pass


@dataclass
class _RunState:
    session_id: int
    session_name: str
    iface: str
    started_at: "object"
    engine: LiveCaptureEngine
    stop_event: threading.Event
    thread: threading.Thread
    error: Optional[str] = None
    lock: threading.Lock = field(default_factory=threading.Lock)


def _require_scapy():
    try:
        from scapy.all import conf, sniff  # noqa: F401
    except ImportError as exc:
        raise CaptureError(
            "scapy is not installed on the server. Run: pip install scapy "
            "(on Windows you also need Npcap, https://npcap.com/, installed "
            "with 'WinPcap API-compatible mode' checked)."
        ) from exc
    return conf, sniff


def is_elevated() -> Optional[bool]:
    """True/False if we can tell, None if we can't (non-Windows: sniffing
    just needs root/cap_net_raw, which we have no cheap way to check)."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return None


class CaptureManager:
    """Process-wide singleton; use the module-level `manager` instance."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Optional[_RunState] = None

    def list_interfaces(self, include_invalid: bool = False) -> tuple[list[InterfaceRow], int]:
        conf, _sniff = _require_scapy()
        return collect_interfaces(conf.ifaces.values(), include_invalid=include_invalid)

    def start(
        self,
        iface: str,
        bpf: Optional[str] = None,
        name: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> CaptureSession:
        if not iface:
            raise CaptureError("iface is required")

        with self._lock:
            if self._state is not None:
                raise CaptureAlreadyRunning(
                    f"A capture is already running on '{self._state.iface}' "
                    f"(session {self._state.session_id}). Stop it first."
                )

            _conf, sniff = _require_scapy()

            from django.conf import settings

            resolved_window = window_seconds or getattr(
                settings, "MESHVIEW_LIVE_WINDOW_SECONDS", 60
            )

            session = CaptureSession.objects.create(
                name=name or f"live: {iface}",
                source=CaptureSession.Source.LIVE,
                interface=iface,
                started_at=django_timezone.now(),
                is_active=True,
            )

            engine = LiveCaptureEngine(session=session, window_seconds=resolved_window)
            stop_event = threading.Event()

            thread = threading.Thread(
                target=self._run,
                args=(session, engine, stop_event, iface, bpf, sniff),
                daemon=True,
                name=f"meshview-capture-{session.id}",
            )

            self._state = _RunState(
                session_id=session.id,
                session_name=session.name,
                iface=iface,
                started_at=session.started_at,
                engine=engine,
                stop_event=stop_event,
                thread=thread,
            )
            thread.start()
            return session

    def _run(self, session, engine, stop_event, iface, bpf, sniff) -> None:
        # engine.handle_frame() (called from the sniff callback below, on
        # this thread) and engine.tick() (called from the ticker thread)
        # can each trigger engine.flush(), which reads and rewrites the
        # Host/Conversation aggregates. Without serializing the two, they
        # can race on those aggregates -- and, on SQLite, race for the
        # write lock -- exactly like `capture_live.py`'s identical
        # sniff-thread-plus-ticker-thread split would if two of its
        # flushes ever landed at the same instant. A lock per capture
        # keeps it to one flush at a time without slowing either thread
        # down in the common case (flush is fast; frames arrive one at a
        # time either way).
        flush_lock = threading.Lock()

        ticker = threading.Thread(
            target=self._tick_loop, args=(engine, stop_event, flush_lock), daemon=True
        )
        ticker.start()

        def _on_packet(pkt):
            try:
                raw = bytes(pkt)
                ts = django_timezone.datetime.fromtimestamp(
                    float(pkt.time), tz=django_timezone.get_current_timezone()
                )
            except Exception:  # noqa: BLE001 - never let one bad frame kill the capture
                return
            with flush_lock:
                engine.handle_frame(raw, ts)

        error: Optional[str] = None
        try:
            sniff(
                iface=iface,
                filter=bpf,
                prn=_on_packet,
                store=False,
                stop_filter=lambda _pkt: stop_event.is_set(),
            )
        except PermissionError:
            error = (
                "Permission denied opening the interface. On Windows, run the "
                "server elevated (as Administrator); on Linux/Mac, run it with "
                "sudo or grant cap_net_raw to the python binary."
            )
        except Exception as exc:  # noqa: BLE001 - surface it via status(), don't crash the thread silently
            error = str(exc) or exc.__class__.__name__
        finally:
            stop_event.set()
            ticker.join(timeout=engine.flush_interval + 2)
            with flush_lock:
                engine.flush()
            session.is_active = False
            session.ended_at = django_timezone.now()
            session.save(update_fields=["is_active", "ended_at"])
            with self._lock:
                if self._state is not None and self._state.session_id == session.id:
                    if error:
                        self._state.error = error
                    else:
                        # Clean stop (via stop_event from stop()): clear
                        # state so a new capture can start right away.
                        self._state = None

    def _tick_loop(
        self, engine: LiveCaptureEngine, stop_event: threading.Event, flush_lock: threading.Lock
    ) -> None:
        while not stop_event.wait(engine.flush_interval):
            try:
                with flush_lock:
                    engine.tick()
            except Exception:  # noqa: BLE001 - a transient DB hiccup shouldn't kill the ticker
                pass

    def stop(self, timeout: float = 10.0) -> dict:
        with self._lock:
            state = self._state
            if state is None:
                raise CaptureNotRunning("No capture is currently running.")
            state.stop_event.set()
            thread = state.thread

        thread.join(timeout=timeout)

        with self._lock:
            # If the thread already cleared self._state in _run()'s finally
            # block, there's nothing left to clean up. If it's still set
            # (thread didn't finish within `timeout`), leave it -- the
            # thread will clear it itself once sniff() actually returns.
            still_running = self._state is not None and self._state.session_id == state.session_id
            stats = state.engine.stats

        return {
            "session_id": state.session_id,
            "stopped": not still_running,
            "packet_count": stats.packet_count,
            "byte_count": stats.byte_count,
            "parse_error_count": stats.parse_error_count,
        }

    def status(self) -> dict:
        with self._lock:
            state = self._state
            if state is None:
                return {"running": False}

            stats: LiveCaptureStats = state.engine.stats
            return {
                "running": state.error is None,
                "session_id": state.session_id,
                "session_name": state.session_name,
                "iface": state.iface,
                "started_at": state.started_at,
                "packet_count": stats.packet_count,
                "byte_count": stats.byte_count,
                "parse_error_count": stats.parse_error_count,
                "error": state.error,
            }


# Process-wide singleton. Gunicorn/uvicorn workers each get their own
# (this app runs as a single `runserver` process, per the README), so
# there's exactly one of these per running server.
manager = CaptureManager()
