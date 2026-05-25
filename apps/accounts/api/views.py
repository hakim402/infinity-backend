"""
apps/accounts/api/views.py
───────────────────────────
Thin view layer — each view does exactly three things:
  1. Deserialise & validate input.
  2. Call a service function.
  3. Serialise & return the response.

No business logic lives here.
"""

from __future__ import annotations

import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.accounts.api.serializers import (
    ChangePasswordSerializer,
    ClientRegistrationSerializer,
    LogoutSerializer,
    MagicLinkRequestSerializer,
    RefreshTokenSerializer,
    UserMeSerializer,
    UserUpdateSerializer,
)
from apps.accounts.permissions import IsClientUser
from apps.accounts.services import auth_service, user_service

log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _request_meta(request: Request) -> dict:
    """
    Extract IP address and User-Agent from an incoming DRF request.

    Handles reverse-proxy deployments (X-Forwarded-For) by taking only the
    first IP in the header to prevent header-spoofing with comma chains.
    """
    ip = (
        request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
        or request.META.get("REMOTE_ADDR")
    )
    return {
        "ip_address": ip or None,
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
    }


# ──────────────────────────────────────────────────────────────────────────────
# CUSTOM THROTTLE SCOPES
# Each scope maps to a rate defined in REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"]
# ──────────────────────────────────────────────────────────────────────────────

class RegistrationThrottle(AnonRateThrottle):
    """5 registration requests per minute per IP."""
    scope = "registration"


class MagicLinkRequestThrottle(AnonRateThrottle):
    """5 magic-link requests per minute per IP."""
    scope = "magic_link_request"


class MagicLinkVerifyThrottle(AnonRateThrottle):
    """20 verify attempts per minute per IP."""
    scope = "magic_link_verify"


# ──────────────────────────────────────────────────────────────────────────────
# 0. CLIENT REGISTRATION  —  POST /api/v1/auth/register/
# ──────────────────────────────────────────────────────────────────────────────

class ClientRegistrationView(APIView):
    """
    Register a new client user.

    Creates the User record, generates a MagicLinkToken, and sends a sign-in
    email via Celery. Returns HTTP 201 with a generic message — no tokens are
    issued immediately; the user must click the magic link to authenticate.

    Rate limit: 5 requests/minute per IP.
    """

    permission_classes     = []
    authentication_classes = []
    throttle_classes       = [RegistrationThrottle]

    def post(self, request: Request) -> Response:
        serializer = ClientRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        auth_service.register_client(
            email=serializer.validated_data["email"],
            full_name=serializer.validated_data["full_name"],
        )

        return Response(
            {
                "detail": (
                    "Account created. Please check your email for a sign-in link "
                    "to verify your address and complete login."
                )
            },
            status=status.HTTP_201_CREATED,
        )


# ──────────────────────────────────────────────────────────────────────────────
# 1. REQUEST MAGIC LINK  —  POST /api/v1/auth/magic/request/
# ──────────────────────────────────────────────────────────────────────────────

class MagicLinkRequestView(APIView):
    """
    Issue a one-time magic login link for the provided email address.

    Always returns HTTP 200 with a generic message — never reveals whether
    the email is registered (anti-enumeration protection).
    """

    permission_classes     = []
    authentication_classes = []
    throttle_classes       = [MagicLinkRequestThrottle]

    def post(self, request: Request) -> Response:
        serializer = MagicLinkRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        auth_service.request_magic_link(
            email=serializer.validated_data["email"],
        )

        return Response(
            {"detail": "If an account exists, a link has been sent."},
            status=status.HTTP_200_OK,
        )


# ──────────────────────────────────────────────────────────────────────────────
# 2. VERIFY MAGIC LINK  —  GET /api/v1/auth/magic/verify/?token=<raw>
# ──────────────────────────────────────────────────────────────────────────────

class MagicLinkVerifyView(APIView):
    """
    Exchange a raw magic-link token for a JWT access/refresh pair.

    Accepts the token as a query parameter (GET) so that the frontend can
    redirect the user directly to this URL after clicking the email link.
    """

    permission_classes     = []
    authentication_classes = []
    throttle_classes       = [MagicLinkVerifyThrottle]

    def get(self, request: Request) -> Response:
        token = request.query_params.get("token", "").strip()

        if not token or len(token) < 32:
            return Response(
                {"detail": "A valid token query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        result = auth_service.verify_magic_link(
            raw_token=token,
            meta=_request_meta(request),
        )

        return Response(
            {
                "access":  result["access"],
                "refresh": result["refresh"],
                "user":    UserMeSerializer(result["user"]).data,
            },
            status=status.HTTP_200_OK,
        )


# ──────────────────────────────────────────────────────────────────────────────
# 3. REFRESH TOKEN  —  POST /api/v1/auth/token/refresh/
# ──────────────────────────────────────────────────────────────────────────────

class TokenRefreshView(APIView):
    """
    Rotate a refresh token and return a new access/refresh pair.

    Extends SimpleJWT's default behaviour with:
      - Revocation checking against UserRefreshToken.
      - Device-aware session tracking on rotation.
      - Escalation to full session wipe on revoked-token replay.
    """

    permission_classes     = []
    authentication_classes = []
    throttle_classes       = [AnonRateThrottle]

    def post(self, request: Request) -> Response:
        serializer = RefreshTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        result = auth_service.refresh_access_token(
            raw_refresh=serializer.validated_data["refresh"],
            meta=_request_meta(request),
        )

        return Response(
            {
                "access":  result["access"],
                "refresh": result["refresh"],
                "user":    UserMeSerializer(result["user"]).data,
            },
            status=status.HTTP_200_OK,
        )


# ──────────────────────────────────────────────────────────────────────────────
# 4. LOGOUT  —  POST /api/v1/auth/logout/
# ──────────────────────────────────────────────────────────────────────────────

class LogoutView(APIView):
    """
    Revoke the provided refresh token (current device) or all sessions.

    Requires a valid JWT access token in the Authorization header.
    Supports an optional `all_devices: true` flag for full session wipe.
    """

    permission_classes = [IsClientUser]
    throttle_classes   = [UserRateThrottle]

    def post(self, request: Request) -> Response:
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        auth_service.logout(
            user=request.user,
            raw_refresh=serializer.validated_data["refresh"],
            all_devices=serializer.validated_data.get("all_devices", False),
        )

        return Response(
            {"detail": "Successfully logged out."},
            status=status.HTTP_200_OK,
        )


# ──────────────────────────────────────────────────────────────────────────────
# 5 & 6. CURRENT USER  —  GET + PATCH /api/v1/users/me/
# ──────────────────────────────────────────────────────────────────────────────

class UserMeView(APIView):
    """
    GET  → Return the authenticated user's full profile.
    PATCH → Partially update full_name and/or profile fields.

    email and tenant are read-only; any attempt to change them is rejected
    at the serializer validation level.
    """

    permission_classes = [IsClientUser]
    throttle_classes   = [UserRateThrottle]

    def get(self, request: Request) -> Response:
        user = user_service.get_me(request.user)
        return Response(
            UserMeSerializer(user).data,
            status=status.HTTP_200_OK,
        )

    def patch(self, request: Request) -> Response:
        serializer = UserUpdateSerializer(
            request.user,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)

        updated_user = user_service.update_me(
            user=request.user,
            validated_data=serializer.validated_data,
        )

        return Response(
            UserMeSerializer(updated_user).data,
            status=status.HTTP_200_OK,
        )


# ──────────────────────────────────────────────────────────────────────────────
# 7. CHANGE PASSWORD  —  POST /api/v1/auth/change-password/
# ──────────────────────────────────────────────────────────────────────────────

class ChangePasswordView(APIView):
    """
    Allow a client user to set or change their password.

    Magic-link-only users (no usable password) may omit current_password.
    The new password is validated against Django's AUTH_PASSWORD_VALIDATORS
    in the serializer before reaching the service layer.
    """

    permission_classes = [IsClientUser]
    throttle_classes   = [UserRateThrottle]

    def post(self, request: Request) -> Response:
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        auth_service.change_password(
            user=request.user,
            current_password=serializer.validated_data.get("current_password", ""),
            new_password=serializer.validated_data["new_password"],
        )

        return Response(
            {"detail": "Password updated successfully."},
            status=status.HTTP_200_OK,
        )