"""
Phase 4: live capture via Npcap (Windows) / libpcap (Linux/Mac).

This is the one file in Phase 4 that genuinely cannot be run or tested
in the sandbox this was built in -- it needs a real interface, Npcap
installed, and (on Windows) an elevated shell, none of which exist
there. It's kept deliberately thin for exactly that reason: every
other piece of Phase 4 (the rolling-window logic in capture/engine.py,
the interface table in capture/interfaces.py, the WebSocket feed in
consumers.py + snapshot.py) has been exercised without a NIC.
This file's only job is "get raw bytes + a timestamp out of scapy, and
a stop signal out of Ctrl+C" -- everything else is delegated.

Usage
-----
    # See available interfaces first (friendly name, IPv4, description)
    python manage.py capture_live --list-interfaces

    # Windows: run this shell as Administrator, then e.g.
    python manage.py capture_live --iface "Ethernet"

    # Linux/Mac: run with sudo, or grant cap_net_raw to the python binary
    sudo python manage.py capture_live --iface eth0 --bpf "tcp or udp"

Requires scapy (`pip install scapy`) and, on Windows, Npcap
(https://npcap.com/) installed with "WinPcap API-compatible mode"
checked during install.
"""

from __future__ import annotations

import signal
import sys
import threading

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone as django_timezone

from netcap.capture.engine import LiveCaptureEngine
from netcap.capture.interfaces import collect_interfaces, format_interface_table
from netcap.models import CaptureSession


class Command(BaseCommand):
    help = "Capture live traffic via Npcap/libpcap into a new live CaptureSession."

    def add_arguments(self, parser):
        parser.add_argument(
            "--iface", help="Interface name/description to capture on (see --list-interfaces)"
        )
        parser.add_argument(
            "--list-interfaces", action="store_true", help="List capture-capable interfaces and exit"
        )
        parser.add_argument(
            "--all", action="store_true",
            help="With --list-interfaces, also show interfaces scapy considers unusable "
                 "(no IP/MAC, or no matching Npcap device)",
        )
        parser.add_argument("--bpf", default=None, help="Optional BPF filter, e.g. 'tcp or udp'")
        parser.add_argument("--name", default=None, help="Name for the CaptureSession")
        parser.add_argument(
            "--window-seconds", type=int, default=None,
            help="Rolling window fed to the scene (default: MESHVIEW_LIVE_WINDOW_SECONDS, 60)",
        )

    def handle(self, *args, **options):
        try:
            from scapy.all import conf
        except ImportError:
            raise CommandError(
                "scapy is not installed. Run: pip install scapy\n"
                "On Windows you also need Npcap (https://npcap.com/) installed "
                "with 'WinPcap API-compatible mode' checked during setup."
            )

        if options["list_interfaces"]:
            rows, hidden = collect_interfaces(conf.ifaces.values(), include_invalid=options["all"])
            self.stdout.write(format_interface_table(rows, hidden))
            return

        iface = options["iface"]
        if not iface:
            raise CommandError("pass --iface (see --list-interfaces for names)")

        if sys.platform == "win32":
            self._warn_if_not_admin()

        from django.conf import settings

        window_seconds = options["window_seconds"] or getattr(
            settings, "MESHVIEW_LIVE_WINDOW_SECONDS", 60
        )

        session = CaptureSession.objects.create(
            name=options["name"] or f"live: {iface}",
            source=CaptureSession.Source.LIVE,
            interface=iface,
            started_at=django_timezone.now(),
            is_active=True,
        )
        self.stdout.write(self.style.SUCCESS(f"Started session '{session.name}' (id={session.id})"))
        self.stdout.write(
            f"Scene: http://127.0.0.1:8000/scene/?session={session.id}  "
            f"(rolling {window_seconds}s window)"
        )
        self.stdout.write("Press Ctrl+C to stop.")

        # No push hook here on purpose: this process writes the DB and the
        # web server process (SceneConsumer) watches it. An in-memory
        # channel layer can't span the two processes.
        engine = LiveCaptureEngine(session=session, window_seconds=window_seconds)

        stop_event = threading.Event()
        original_handler = signal.getsignal(signal.SIGINT)

        def _handle_sigint(signum, frame):
            self.stdout.write("\nStopping capture...")
            stop_event.set()

        signal.signal(signal.SIGINT, _handle_sigint)

        ticker = threading.Thread(target=self._tick_loop, args=(engine, stop_event), daemon=True)
        ticker.start()

        from scapy.all import sniff

        def _on_packet(pkt):
            try:
                raw = bytes(pkt)
                ts = django_timezone.datetime.fromtimestamp(
                    float(pkt.time), tz=django_timezone.get_current_timezone()
                )
            except Exception as exc:  # noqa: BLE001 - never let one bad frame kill the capture
                self.stderr.write(f"skipped unreadable frame: {exc}")
                return
            engine.handle_frame(raw, ts)

        try:
            sniff(
                iface=iface,
                filter=options["bpf"],
                prn=_on_packet,
                store=False,
                stop_filter=lambda _pkt: stop_event.is_set(),
            )
        except PermissionError:
            raise CommandError(
                "Permission denied opening the interface. On Windows, re-run this "
                "shell as Administrator; on Linux/Mac, use sudo (or grant "
                "cap_net_raw to the python binary)."
            )
        finally:
            signal.signal(signal.SIGINT, original_handler)
            stop_event.set()
            engine.flush()
            session.is_active = False
            session.ended_at = django_timezone.now()
            session.save()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Stopped. {engine.stats.packet_count} packets captured, "
                    f"{engine.stats.parse_error_count} parse errors."
                )
            )

    def _tick_loop(self, engine: LiveCaptureEngine, stop_event: threading.Event) -> None:
        while not stop_event.wait(engine.flush_interval):
            engine.tick()

    def _warn_if_not_admin(self) -> None:
        try:
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():  # type: ignore[attr-defined]
                self.stdout.write(
                    self.style.WARNING(
                        "Not running as Administrator -- Npcap will likely fail to "
                        "open the interface. Re-run this shell elevated."
                    )
                )
        except Exception:
            pass
