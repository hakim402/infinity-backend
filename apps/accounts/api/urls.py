from django.urls import path

from .views import (
    ActiveSessionsView,
    ChangePasswordView,
    GoogleOAuthView,
    LoginView,
    LogoutView,
    MagicLinkRequestView,
    MagicLinkVerifyView,
    MeView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegisterView,
    RevokeSessionView,
    TokenRefreshView,
    UpdateMeView,
    VerifyEmailView,
)

app_name = "accounts"

urlpatterns = [
    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/verify-email/", VerifyEmailView.as_view(), name="verify-email"),
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("auth/magic-link/request/", MagicLinkRequestView.as_view(), name="magic-link-request"),
    path("auth/magic-link/verify/", MagicLinkVerifyView.as_view(), name="magic-link-verify"),
    path("auth/password-reset/request/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("auth/password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("auth/google/", GoogleOAuthView.as_view(), name="google-oauth"),
    path("auth/me/", MeView.as_view(), name="me"),
    path("auth/me/update/", UpdateMeView.as_view(), name="me-update"),
    path("auth/me/change-password/", ChangePasswordView.as_view(), name="change-password"),
    path("auth/sessions/", ActiveSessionsView.as_view(), name="sessions"),
    path("auth/sessions/<uuid:session_id>/revoke/", RevokeSessionView.as_view(), name="session-revoke"),
]
