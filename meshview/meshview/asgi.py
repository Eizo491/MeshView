import os

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "meshview.settings")
django.setup()

from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402
from django.core.asgi import get_asgi_application  # noqa: E402

from netcap.routing import websocket_urlpatterns  # noqa: E402

application = ProtocolTypeRouter(
    {
        "http": get_asgi_application(),
        # Live capture (Phase 4) pushes hosts/conversations to the 3D
        # scene as the capture engine flushes. See netcap/consumers.py.
        "websocket": URLRouter(websocket_urlpatterns),
    }
)
