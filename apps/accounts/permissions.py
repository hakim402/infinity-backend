"""
apps/accounts/permissions.py
────────────────────────────
Custom DRF permission classes for the client-facing authentication API.
"""

from __future__ import annotations

from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView


class IsClientUser(BasePermission):
    """
    Grants access only to authenticated users that satisfy ALL of:
      - is_authenticated      → carries a valid JWT
      - role == 'client'      → not an admin or superuser sneaking through the API
      - is_active == True     → account has not been deactivated
      - deleted_at is None    → account has not been soft-deleted

    This permission is self-contained: combining it with IsAuthenticated is
    redundant but harmless.
    """

    message = "Access restricted to active client accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and user.role == "client"
            and user.is_active
            and user.deleted_at is None
        )


class IsClientUserOrReadOnly(BasePermission):
    """
    SAFE methods (GET, HEAD, OPTIONS) are permitted for any authenticated user.
    Write methods require the full IsClientUser check.

    Useful for future public-readable endpoints (e.g. public profile pages).
    """

    message = "Write access restricted to active client accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        from rest_framework.permissions import SAFE_METHODS

        if request.method in SAFE_METHODS:
            return bool(request.user and request.user.is_authenticated)

        user = request.user
        return bool(
            user
            and user.is_authenticated
            and user.role == "client"
            and user.is_active
            and user.deleted_at is None
        )