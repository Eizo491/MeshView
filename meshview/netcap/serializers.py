"""
Serializers for the Phase 2 API.

Packet gets two serializers on purpose: the table view only needs the
columns it actually displays (keeps list responses small when a
session has tens of thousands of packets), while the details pane
wants everything, including the payload preview and parse status.
"""

from rest_framework import serializers

from .models import CaptureSession, Conversation, Host, Packet


class CaptureSessionSerializer(serializers.ModelSerializer):
    packet_count = serializers.IntegerField(source="packets.count", read_only=True)

    class Meta:
        model = CaptureSession
        fields = [
            "id", "name", "source", "interface", "original_filename",
            "started_at", "ended_at", "is_active", "packet_count",
        ]


class PacketListSerializer(serializers.ModelSerializer):
    """Columns for the packet table."""

    class Meta:
        model = Packet
        fields = [
            "id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "length", "encrypted", "is_anomaly", "info",
        ]


class PacketDetailSerializer(serializers.ModelSerializer):
    """Everything, for the details pane."""

    class Meta:
        model = Packet
        fields = "__all__"


class HostSerializer(serializers.ModelSerializer):
    class Meta:
        model = Host
        fields = [
            "id", "ip_address", "is_local", "packet_count", "byte_count",
            "first_seen", "last_seen",
        ]


class ConversationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Conversation
        fields = [
            "id", "src_ip", "dst_ip", "protocol", "encrypted", "packet_count",
            "byte_count", "first_seen", "last_seen",
        ]


class PcapUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    name = serializers.CharField(required=False, allow_blank=True, max_length=255)

    def validate_file(self, value):
        if not value.name.lower().endswith(".pcap"):
            raise serializers.ValidationError(
                "Only classic .pcap files are supported (not .pcapng)."
            )
        return value


class CaptureStartSerializer(serializers.Serializer):
    """POST body for /api/capture/start/. Mirrors `capture_live`'s
    --iface/--bpf/--name/--window-seconds flags."""

    iface = serializers.CharField(max_length=200)
    bpf = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    name = serializers.CharField(required=False, allow_blank=True, max_length=255)
    window_seconds = serializers.IntegerField(required=False, min_value=1, max_value=3600)
