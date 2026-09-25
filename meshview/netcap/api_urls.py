from rest_framework.routers import DefaultRouter

from .api_views import (
    CaptureInterfacesView,
    CaptureSessionViewSet,
    CaptureStartView,
    CaptureStatusView,
    CaptureStopView,
    PacketViewSet,
    PcapUploadView,
)
from django.urls import path

router = DefaultRouter()
router.register("sessions", CaptureSessionViewSet, basename="session")
router.register("packets", PacketViewSet, basename="packet")

urlpatterns = router.urls + [
    path("pcap-uploads/", PcapUploadView.as_view(), name="pcap-upload"),
    path("capture/interfaces/", CaptureInterfacesView.as_view(), name="capture-interfaces"),
    path("capture/status/", CaptureStatusView.as_view(), name="capture-status"),
    path("capture/start/", CaptureStartView.as_view(), name="capture-start"),
    path("capture/stop/", CaptureStopView.as_view(), name="capture-stop"),
]
