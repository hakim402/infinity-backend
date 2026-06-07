"""
apps/accounts/api/views.py
───────────────────────
DRF views for every authentication endpoint.

URL map (see urls.py)
─────────────────────
POST   /auth/register/              → RegisterView
POST   /auth/verify-email/          → VerifyEmailView
POST   /auth/login/                 → LoginView
POST   /auth/logout/                → LogoutView
POST   /auth/token/refresh/         → TokenRefreshView
POST   /auth/magic-link/request/    → MagicLinkRequestView
POST   /auth/magic-link/verify/     → MagicLinkVerifyView
POST   /auth/password-reset/request/  → PasswordResetRequestView
POST   /auth/password-reset/confirm/  → PasswordResetConfirmView
POST   /auth/google/                → GoogleOAuthView
GET    /auth/me/                    → MeView
PATCH  /auth/me/update/             → UpdateMeView
POST   /auth/me/change-password/    → ChangePasswordView
GET    /auth/sessions/              → ActiveSessionsView
DELETE /auth/sessions/<id>/revoke/  → RevokeSessionView
"""

from __future__ import annotations

from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ..models import UserRefreshToken
from .serializers import (
    ChangePasswordSerializer,
    EmailLoginSerializer,
    EmailVerifySerializer,
    GoogleOAuthSerializer,
    LogoutSerializer,
    MagicLinkRequestSerializer,
    MagicLinkVerifySerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RevokeSessionSerializer,
    TokenRefreshSerializer,
    UserMeSerializer,
    UserRegistrationSerializer,
    UserRefreshTokenSerializer,
    UserUpdateSerializer,
)
from ..services.services import AuthService


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _ok(data: dict | None = None, status_code: int = status.HTTP_200_OK) -> Response:
    payload = {"success": True}
    if data:
        payload.update(data)
    return Response(payload, status=status_code)


def _created(data: dict) -> Response:
    return _ok(data, status.HTTP_201_CREATED)


# ──────────────────────────────────────────────────────────────────────────────
# 1. REGISTRATION
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class RegisterView(APIView):
    """
    POST /auth/register/
    Create a new CLIENT account and send an email verification link.
    Throttled to 5 requests/minute (see settings.REST_FRAMEWORK).
    """

    permission_classes = [AllowAny]
    throttle_scope     = "registration"

    @extend_schema(
        request=UserRegistrationSerializer,
        responses={
            201: OpenApiResponse(description="User created; verification email sent."),
            400: OpenApiResponse(description="Validation error."),
        },
        summary="Register a new user",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = AuthService.register(serializer.validated_data)

        return _created({
            "message": (
                "Account created. "
                "Please check your email to verify your address."
            ),
            "user_id": str(user.id),
            "email":   user.email,
        })


# ──────────────────────────────────────────────────────────────────────────────
# 2. EMAIL VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class VerifyEmailView(APIView):
    """
    POST /auth/verify-email/
    Accepts the raw token from the verification link.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        request=EmailVerifySerializer,
        responses={200: OpenApiResponse(description="Email verified.")},
        summary="Verify email address",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = EmailVerifySerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        ev_token = serializer.context["ev_token"]
        AuthService.verify_email(ev_token)

        return _ok({"message": "Email verified successfully. You may now log in."})


# ──────────────────────────────────────────────────────────────────────────────
# 3. EMAIL / PASSWORD LOGIN
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class LoginView(APIView):
    """
    POST /auth/login/
    Returns an access + refresh JWT pair on valid credentials.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        request=EmailLoginSerializer,
        responses={
            200: OpenApiResponse(description="Access + refresh tokens."),
            400: OpenApiResponse(description="Invalid credentials."),
        },
        summary="Email / password login",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = EmailLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user   = serializer.validated_data["user"]
        tokens = AuthService.login(user, request)

        return _ok({
            "message":           "Login successful.",
            "access":            tokens["access"],
            "refresh":           tokens["refresh"],
            "access_expires_at": tokens["access_expires_at"].isoformat(),
        })


# ──────────────────────────────────────────────────────────────────────────────
# 4. LOGOUT
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class LogoutView(APIView):
    """
    POST /auth/logout/
    Revokes the supplied refresh token (session).
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=LogoutSerializer,
        responses={200: OpenApiResponse(description="Logged out.")},
        summary="Logout (revoke session)",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        AuthService.logout(serializer.validated_data["refresh"], request.user)

        return _ok({"message": "Logged out successfully."})


# ──────────────────────────────────────────────────────────────────────────────
# 5. TOKEN REFRESH
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class TokenRefreshView(APIView):
    """
    POST /auth/token/refresh/
    Exchange a valid refresh token for a new access (+ rotated refresh) token.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        request=TokenRefreshSerializer,
        responses={200: OpenApiResponse(description="New access token.")},
        summary="Refresh access token",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = TokenRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tokens = AuthService.refresh_token(
            serializer.validated_data["refresh"], request
        )

        return _ok({
            "access":            tokens["access"],
            "refresh":           tokens["refresh"],
            "access_expires_at": tokens["access_expires_at"].isoformat(),
        })


# ──────────────────────────────────────────────────────────────────────────────
# 6. MAGIC LINK — REQUEST
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class MagicLinkRequestView(APIView):
    """
    POST /auth/magic-link/request/
    Sends a one-time login link to the given email.
    Always returns 200 to prevent email enumeration.
    """

    permission_classes = [AllowAny]
    throttle_scope     = "magic_link_request"

    @extend_schema(
        request=MagicLinkRequestSerializer,
        responses={200: OpenApiResponse(description="Magic link sent (if email exists).")},
        summary="Request passwordless magic link",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = MagicLinkRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        AuthService.magic_link_request(serializer.validated_data["email"])

        return _ok({
            "message": (
                "If that email is registered you will receive a sign-in link shortly."
            )
        })


# ──────────────────────────────────────────────────────────────────────────────
# 7. MAGIC LINK — VERIFY
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class MagicLinkVerifyView(APIView):
    """
    POST /auth/magic-link/verify/
    Consumes the token from the magic-link URL and returns a JWT pair.
    """

    permission_classes = [AllowAny]
    throttle_scope     = "magic_link_verify"

    @extend_schema(
        request=MagicLinkVerifySerializer,
        responses={200: OpenApiResponse(description="Access + refresh tokens.")},
        summary="Verify magic link token",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = MagicLinkVerifySerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        ml_token = serializer.context["ml_token"]
        tokens   = AuthService.magic_link_verify(ml_token, request)

        return _ok({
            "message":           "Login successful.",
            "access":            tokens["access"],
            "refresh":           tokens["refresh"],
            "access_expires_at": tokens["access_expires_at"].isoformat(),
        })


# ──────────────────────────────────────────────────────────────────────────────
# 8. PASSWORD RESET — REQUEST
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class PasswordResetRequestView(APIView):
    """
    POST /auth/password-reset/request/
    Sends a password-reset email.
    Always returns 200.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={200: OpenApiResponse(description="Reset email sent (if exists).")},
        summary="Request password reset",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        AuthService.password_reset_request(serializer.validated_data["email"])

        return _ok({
            "message": (
                "If that email is registered you will receive a password-reset link."
            )
        })


# ──────────────────────────────────────────────────────────────────────────────
# 9. PASSWORD RESET — CONFIRM
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class PasswordResetConfirmView(APIView):
    """
    POST /auth/password-reset/confirm/
    Validates the reset token and sets the new password.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses={200: OpenApiResponse(description="Password updated.")},
        summary="Confirm password reset",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)

        reset_token  = serializer.context["reset_token"]
        new_password = serializer.validated_data["password"]
        AuthService.password_reset_confirm(reset_token, new_password)

        return _ok({"message": "Password updated successfully. Please log in."})


# ──────────────────────────────────────────────────────────────────────────────
# 10. GOOGLE OAUTH2
# ──────────────────────────────────────────────────────────────────────────────

@method_decorator(never_cache, name="dispatch")
class GoogleOAuthView(APIView):
    """
    POST /auth/google/

    Next.js integration
    -------------------
    1. Install: npm install @react-oauth/google
    2. Wrap your app in <GoogleOAuthProvider clientId="...">
    3. Use <GoogleLogin onSuccess={resp => postCredential(resp.credential)} />
    4. POST { credential: resp.credential } to this endpoint.
    5. Store the returned access + refresh tokens in httpOnly cookies or
       a secure state manager.

    This view verifies the Google ID token with Google's public keys and
    creates/links the User automatically.
    """

    permission_classes = [AllowAny]

    @extend_schema(
        request=GoogleOAuthSerializer,
        responses={
            200: OpenApiResponse(description="Access + refresh tokens."),
            401: OpenApiResponse(description="Invalid Google credential."),
        },
        summary="Google OAuth2 sign-in",
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = GoogleOAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        tokens = AuthService.google_oauth(
            serializer.validated_data["credential"], request
        )

        return _ok({
            "message":           "Google sign-in successful.",
            "access":            tokens["access"],
            "refresh":           tokens["refresh"],
            "access_expires_at": tokens["access_expires_at"].isoformat(),
        })


# ──────────────────────────────────────────────────────────────────────────────
# 11. PROFILE — ME
# ──────────────────────────────────────────────────────────────────────────────

class MeView(APIView):
    """
    GET /auth/me/
    Returns the authenticated user's full profile.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: UserMeSerializer},
        summary="Get current user profile",
        tags=["Profile"],
    )
    def get(self, request):
        serializer = UserMeSerializer(request.user)
        return Response(serializer.data)


# ──────────────────────────────────────────────────────────────────────────────
# 12. PROFILE — UPDATE
# ──────────────────────────────────────────────────────────────────────────────

class UpdateMeView(APIView):
    """
    PATCH /auth/me/update/
    Partially update the current user's name and/or profile.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=UserUpdateSerializer,
        responses={200: UserMeSerializer},
        summary="Update current user profile",
        tags=["Profile"],
    )
    def patch(self, request):
        serializer = UserUpdateSerializer(
            request.user,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(UserMeSerializer(request.user).data)


# ──────────────────────────────────────────────────────────────────────────────
# 13. CHANGE PASSWORD
# ──────────────────────────────────────────────────────────────────────────────

class ChangePasswordView(APIView):
    """
    POST /auth/me/change-password/
    Change password while authenticated.  All other sessions are revoked.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=ChangePasswordSerializer,
        responses={200: OpenApiResponse(description="Password changed.")},
        summary="Change password",
        tags=["Profile"],
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)

        # Pass current refresh so the active session is preserved
        current_refresh = serializer.validated_data.get("current_refresh")
        AuthService.change_password(
            request.user,
            serializer.validated_data["new_password"],
            current_refresh=current_refresh,
        )

        return _ok({"message": "Password changed successfully."})


# ──────────────────────────────────────────────────────────────────────────────
# 14. ACTIVE SESSIONS
# ──────────────────────────────────────────────────────────────────────────────

class ActiveSessionsView(APIView):
    """
    GET /auth/sessions/
    List all non-revoked, non-expired sessions for the current user.
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: UserRefreshTokenSerializer(many=True)},
        summary="List active sessions",
        tags=["Sessions"],
    )
    def get(self, request):
        from django.utils import timezone as tz

        sessions = UserRefreshToken.objects.filter(
            user=request.user,
            revoked=False,
            expires_at__gt=tz.now(),
        ).order_by("-last_used_at")

        serializer = UserRefreshTokenSerializer(sessions, many=True)
        return Response({"sessions": serializer.data})


# ──────────────────────────────────────────────────────────────────────────────
# 15. REVOKE SESSION
# ──────────────────────────────────────────────────────────────────────────────

class RevokeSessionView(APIView):
    """
    DELETE /auth/sessions/<id>/revoke/
    Revoke a specific session (device logout).
    """

    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: OpenApiResponse(description="Session revoked.")},
        summary="Revoke a specific session",
        tags=["Sessions"],
    )
    def delete(self, request, session_id):
        try:
            session = UserRefreshToken.objects.get(
                id=session_id, user=request.user
            )
        except UserRefreshToken.DoesNotExist:
            return Response(
                {"detail": "Session not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        session.revoke()
        return _ok({"message": "Session revoked successfully."})