from django.urls import re_path

from . import consumers

websocket_urlpatterns = [
    re_path(r"^ws/scene/(?P<session_id>\d+)/$", consumers.SceneConsumer.as_asgi()),
]
