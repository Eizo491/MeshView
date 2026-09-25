"""
Page routes for the browser-facing packet table + filters + details
pane (spec section 4's Core features). The API itself lives in
api_urls.py, mounted separately at /api/.
"""

from django.urls import path

from . import views

urlpatterns = [
    path("", views.PacketTableView.as_view(), name="packet-table"),
    path("scene/", views.SceneView.as_view(), name="scene"),
]
