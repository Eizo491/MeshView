from django.contrib import admin

from .models import CaptureSession, Conversation, Host, Packet


@admin.register(CaptureSession)
class CaptureSessionAdmin(admin.ModelAdmin):
    list_display = ("name", "source", "started_at", "ended_at", "is_active")
    list_filter = ("source", "is_active")


@admin.register(Packet)
class PacketAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "session", "protocol", "src_ip", "src_port", "dst_ip", "dst_port", "length", "encrypted")
    list_filter = ("protocol", "encrypted", "is_anomaly", "session")
    search_fields = ("src_ip", "dst_ip", "info")


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "session", "packet_count", "byte_count", "is_local")
    list_filter = ("session", "is_local")


@admin.register(Conversation)
class ConversationAdmin(admin.ModelAdmin):
    list_display = ("src_ip", "dst_ip", "protocol", "session", "packet_count", "byte_count")
    list_filter = ("session", "protocol")
