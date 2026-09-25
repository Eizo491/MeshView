"""
Phase 2 API views.

Endpoints (mounted under /api/, see urls.py):

    GET  /api/sessions/                      list capture sessions
    GET  /api/sessions/<id>/                 one session
    GET  /api/sessions/<id>/hosts/           hosts aggregate for a session
    GET  /api/sessions/<id>/conversations/   conversations aggregate for a session
    GET  /api/packets/?session=<id>          packet table, filterable (see PacketViewSet)
    GET  /api/packets/<id>/                  packet details pane
    POST /api/pcap-uploads/                  upload a .pcap, import it, get back a session

Phase 4b adds live-capture control so the web UI can drive the same
Npcap/libpcap capture `capture_live` does, without a second terminal:

    GET  /api/capture/interfaces/            capture-capable NICs (see capture/interfaces.py)
    GET  /api/capture/status/                is a capture running, and its live stats
    POST /api/capture/start/                 start one (iface required; bpf/name/window_seconds optional)
    POST /api/capture/stop/                  stop the running capture

All four proxy to the process-wide `netcap.capture.manager.manager`
singleton -- see that module for why capture lives in-process here
instead of as a second management-command process.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from .capture.manager import (
    CaptureAlreadyRunning,
    CaptureError,
    CaptureNotRunning,
    is_elevated,
    manager as capture_manager,
)
from .models import CaptureSession, Packet
from .pcap.importer import import_pcap_file
from .pcap.reader import PcapFormatError
from .serializers import (
    CaptureSessionSerializer,
    CaptureStartSerializer,
    ConversationSerializer,
    HostSerializer,
    PacketDetailSerializer,
    PacketListSerializer,
    PcapUploadSerializer,
)


class CaptureSessionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CaptureSession.objects.all()
    serializer_class = CaptureSessionSerializer

    @action(detail=True)
    def hosts(self, request, pk=None):
        session = self.get_object()
        hosts = session.hosts.all()
        return Response(HostSerializer(hosts, many=True).data)

    @action(detail=True)
    def conversations(self, request, pk=None):
        session = self.get_object()
        conversations = session.conversations.all()
        return Response(ConversationSerializer(conversations, many=True).data)


class PacketViewSet(viewsets.ReadOnlyModelViewSet):
    """The packet table + details pane, per spec section 4 ("Filter bar
    (ip, port, protocol)").

    Query params on the list endpoint:
        session   -- capture session id (recommended; omitting it searches
                     across every session, which is slow on a big DB)
        protocol  -- exact match, e.g. protocol=DNS
        ip        -- matches either src_ip or dst_ip
        port      -- matches either src_port or dst_port
        encrypted -- "true" / "false"
        anomaly   -- "true" / "false", filters on is_anomaly
        q         -- substring match against the info column
        ordering  -- "timestamp" (default) or "-timestamp" for newest-first,
                     used by the live-capture auto-refresh view
    """

    def get_serializer_class(self):
        return PacketDetailSerializer if self.action == "retrieve" else PacketListSerializer

    def get_queryset(self):
        qs = Packet.objects.select_related("session").all()
        params = self.request.query_params

        session_id = params.get("session")
        if session_id:
            qs = qs.filter(session_id=session_id)

        protocol = params.get("protocol")
        if protocol:
            qs = qs.filter(protocol=protocol.upper())

        ip = params.get("ip")
        if ip:
            from django.db.models import Q

            qs = qs.filter(Q(src_ip=ip) | Q(dst_ip=ip))

        port = params.get("port")
        if port:
            try:
                port_num = int(port)
            except ValueError:
                qs = qs.none()
            else:
                from django.db.models import Q

                qs = qs.filter(Q(src_port=port_num) | Q(dst_port=port_num))

        encrypted = params.get("encrypted")
        if encrypted is not None:
            qs = qs.filter(encrypted=encrypted.lower() in ("1", "true", "yes"))

        anomaly = params.get("anomaly")
        if anomaly is not None:
            qs = qs.filter(is_anomaly=anomaly.lower() in ("1", "true", "yes"))

        query = params.get("q")
        if query:
            qs = qs.filter(info__icontains=query)

        ordering = params.get("ordering")
        if ordering in ("timestamp", "-timestamp"):
            qs = qs.order_by(ordering)

        return qs


class PcapUploadView(APIView):
    """POST a .pcap file (multipart/form-data, field name 'file'); get
    back the new CaptureSession plus import stats. This is the web
    front-end's route to the Phase 1 importer -- spec section 4's
    "PCAP upload and parsing" feature."""

    parser_classes = [MultiPartParser]

    def post(self, request):
        serializer = PcapUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        upload = serializer.validated_data["file"]
        session_name = serializer.validated_data.get("name") or upload.name

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir) / upload.name
            with open(tmp_path, "wb") as fh:
                for chunk in upload.chunks():
                    fh.write(chunk)

            try:
                session, stats = import_pcap_file(str(tmp_path), session_name=session_name)
            except PcapFormatError as exc:
                return Response(
                    {"detail": f"not a supported pcap file: {exc}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return Response(
            {
                "session": CaptureSessionSerializer(session).data,
                "packet_count": stats.packet_count,
                "byte_count": stats.byte_count,
                "parse_error_count": stats.parse_error_count,
            },
            status=status.HTTP_201_CREATED,
        )


class CaptureInterfacesView(APIView):
    """GET the capture-capable NICs for the "Start Capture" interface
    dropdown -- the same list `capture_live --list-interfaces` prints,
    as JSON instead of a text table."""

    def get(self, request):
        try:
            rows, hidden = capture_manager.list_interfaces(
                include_invalid=request.query_params.get("all") in ("1", "true", "yes")
            )
        except CaptureError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {
                "interfaces": [
                    {"name": r.name, "ipv4": r.ipv4, "description": r.description} for r in rows
                ],
                "hidden_count": hidden,
                "elevated": is_elevated(),
            }
        )


class CaptureStatusView(APIView):
    """GET whether a capture is running in this server process, plus its
    live packet/byte/error counts. The scene page polls this only to
    drive the Start/Stop button's own state; the scene graph itself
    updates over the WebSocket, not this endpoint."""

    def get(self, request):
        return Response(capture_manager.status())


class CaptureStartView(APIView):
    """POST {iface, bpf?, name?, window_seconds?} to start a live
    capture in this server process. 409 if one is already running --
    stop it first."""

    def post(self, request):
        serializer = CaptureStartSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            session = capture_manager.start(
                iface=data["iface"],
                bpf=data.get("bpf") or None,
                name=data.get("name") or None,
                window_seconds=data.get("window_seconds"),
            )
        except CaptureAlreadyRunning as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)
        except CaptureError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"session": CaptureSessionSerializer(session).data},
            status=status.HTTP_201_CREATED,
        )


class CaptureStopView(APIView):
    """POST to stop the currently running capture."""

    def post(self, request):
        try:
            result = capture_manager.stop()
        except CaptureNotRunning as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_409_CONFLICT)

        return Response(result)
