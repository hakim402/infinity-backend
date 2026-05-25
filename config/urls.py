# zfix-backend/config/urls.py

from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


urlpatterns = [
    path('admin/', admin.site.urls),
     # Client-facing API v1
    path("api/v1/", include("apps.accounts.api.urls", namespace="accounts")),

    # OpenAPI schema + Swagger UI (restrict or disable in production)
    path("api/schema/",      SpectacularAPIView.as_view(), name="schema"),
    path("api/schema/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
]
