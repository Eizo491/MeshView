from django.views.generic import TemplateView

from .models import CaptureSession


class PacketTableView(TemplateView):
    """Renders the page shell. All data (sessions, packets, details) is
    fetched client-side from the /api/ endpoints in api_urls.py -- this
    view just needs to know whether any sessions exist yet, to decide
    whether to show the upload prompt first."""

    template_name = "netcap/packets.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["has_sessions"] = CaptureSession.objects.exists()
        return context


class SceneView(TemplateView):
    """The 3D network graph (spec section 8). Like PacketTableView, this
    is just a page shell -- Three.js fetches hosts/conversations from
    the API client-side and builds the scene in the browser."""

    template_name = "netcap/scene.html"
