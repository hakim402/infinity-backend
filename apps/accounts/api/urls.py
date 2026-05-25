"""
apps/accounts/api/urls.py
──────────────────────────
URL configuration for the client-facing authentication API.
Mount this under /api/v1/ in the project's root urls.py:

    path("api/v1/", include("apps.accounts.api.urls", namespace="accounts")),
"""

from django.urls import path

from apps.accounts.api import views

app_name = "accounts"

urlpatterns = [
    # ── Registration ──────────────────────────────────────────────────────────
    path(
        "auth/register/",
        views.ClientRegistrationView.as_view(),
        name="register",
    ),

    # ── Magic Link ────────────────────────────────────────────────────────────
    path(
        "auth/magic/request/",
        views.MagicLinkRequestView.as_view(),
        name="magic-request",
    ),
    path(
        "auth/magic/verify/",
        views.MagicLinkVerifyView.as_view(),
        name="magic-verify",
    ),

    # ── Token management ──────────────────────────────────────────────────────
    path(
        "auth/token/refresh/",
        views.TokenRefreshView.as_view(),
        name="token-refresh",
    ),
    path(
        "auth/logout/",
        views.LogoutView.as_view(),
        name="logout",
    ),
    path(
        "auth/change-password/",
        views.ChangePasswordView.as_view(),
        name="change-password",
    ),

    # ── User profile ──────────────────────────────────────────────────────────
    path(
        "users/me/",
        views.UserMeView.as_view(),
        name="me",
    ),
]