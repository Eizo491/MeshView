"""
Data model for Meshview 3D (see Meshview_3D_spec.md section 7).

Design notes
------------
* Host and Conversation are aggregate tables, kept up to date alongside
  Packet writes so the 3D scene and stats dashboard can query small
  summary tables instead of scanning every packet.
* Everything is scoped to a CaptureSession so a live capture and an
  uploaded PCAP never mix in the same graph/timeline.
* Indexes are chosen for the two query patterns the app actually needs:
  "packets in this session, filtered by ip/port/protocol, in time
  order" and "conversations/hosts for this session, ordered by
  traffic volume".
"""

from django.db import models


class CaptureSession(models.Model):
    class Source(models.TextChoices):
        LIVE = "live", "Live capture"
        FILE = "file", "Uploaded PCAP"

    name = models.CharField(max_length=255)
    source = models.CharField(max_length=8, choices=Source.choices)
    interface = models.CharField(
        max_length=100,
        blank=True,
        help_text="Capture interface name, only set for live sessions.",
    )
    original_filename = models.CharField(
        max_length=255,
        blank=True,
        help_text="Original PCAP filename, only set for file sessions.",
    )
    started_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=False)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"{self.name} ({self.source})"


class Packet(models.Model):
    class Protocol(models.TextChoices):
        DNS = "DNS", "DNS"
        HTTP = "HTTP", "HTTP"
        TCP = "TCP", "TCP"
        UDP = "UDP", "UDP"
        ICMP = "ICMP", "ICMP"
        ARP = "ARP", "ARP"
        OTHER = "OTHER", "Other"

    session = models.ForeignKey(
        CaptureSession, on_delete=models.CASCADE, related_name="packets"
    )
    timestamp = models.DateTimeField(db_index=True)

    # Layer 2 (kept for the details pane; not indexed, low cardinality use)
    src_mac = models.CharField(max_length=17, blank=True)
    dst_mac = models.CharField(max_length=17, blank=True)
    ethertype = models.CharField(max_length=10, blank=True)

    # Layer 3 / 4
    src_ip = models.GenericIPAddressField(null=True, blank=True)
    dst_ip = models.GenericIPAddressField(null=True, blank=True)
    src_port = models.PositiveIntegerField(null=True, blank=True)
    dst_port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=8, choices=Protocol.choices)
    ip_protocol_number = models.PositiveSmallIntegerField(
        null=True, blank=True, help_text="Raw IP protocol number (6=TCP, 17=UDP, ...)"
    )

    length = models.PositiveIntegerField(help_text="Total frame length in bytes")
    encrypted = models.BooleanField(default=False)

    info = models.CharField(
        max_length=255, blank=True, help_text="One-line human-readable summary"
    )
    payload_preview = models.CharField(
        max_length=256,
        blank=True,
        help_text="Truncated, safe preview of the payload (see settings.MESHVIEW_PAYLOAD_PREVIEW_BYTES)",
    )

    is_anomaly = models.BooleanField(default=False)
    anomaly_reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["timestamp"]
        indexes = [
            models.Index(fields=["session", "timestamp"]),
            models.Index(fields=["session", "protocol"]),
            models.Index(fields=["session", "src_ip"]),
            models.Index(fields=["session", "dst_ip"]),
            models.Index(fields=["session", "src_port"]),
            models.Index(fields=["session", "dst_port"]),
        ]

    def __str__(self) -> str:
        return f"[{self.protocol}] {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"


class Host(models.Model):
    """Aggregate: one row per IP seen in a session. Feeds 3D node sizing."""

    session = models.ForeignKey(
        CaptureSession, on_delete=models.CASCADE, related_name="hosts"
    )
    ip_address = models.GenericIPAddressField()
    is_local = models.BooleanField(
        default=False, help_text="True for the machine running the capture"
    )
    packet_count = models.PositiveIntegerField(default=0)
    byte_count = models.PositiveBigIntegerField(default=0)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["session", "ip_address"], name="unique_host_per_session"
            )
        ]
        ordering = ["-byte_count"]

    def __str__(self) -> str:
        return self.ip_address


class Conversation(models.Model):
    """Aggregate: one row per (src, dst, protocol) triple. Feeds 3D links."""

    session = models.ForeignKey(
        CaptureSession, on_delete=models.CASCADE, related_name="conversations"
    )
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    protocol = models.CharField(max_length=8, choices=Packet.Protocol.choices)
    encrypted = models.BooleanField(
        default=False,
        help_text="True if any packet in this conversation was classified as encrypted",
    )
    packet_count = models.PositiveIntegerField(default=0)
    byte_count = models.PositiveBigIntegerField(default=0)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["session", "src_ip", "dst_ip", "protocol"],
                name="unique_conversation_per_session",
            )
        ]
        ordering = ["-byte_count"]

    def __str__(self) -> str:
        return f"{self.src_ip} -> {self.dst_ip} [{self.protocol}]"
