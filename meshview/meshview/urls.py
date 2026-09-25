from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("netcap.api_urls")),
    path("", include("netcap.urls")),
]
