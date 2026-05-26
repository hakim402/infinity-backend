"""
apps/accounts/permissions.py
────────────────────────────
Custom DRF permission classes for the authentication API.

Hierarchy
---------
  SUPERADMIN > ADMIN > CLIENT

Each class is self-contained: combining IsAuthenticated is redundant but harmless.
"""

from __future__ import annotations

from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _is_live_user(user) -> bool:
    """
    Returns True when the user object represents a real, non-deleted,
    authenticated account that is currently active and not locked.
    """
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and user.deleted_at is None
        and not user.is_locked
    )


# ──────────────────────────────────────────────────────────────────────────────
# 1. CLIENT
# ──────────────────────────────────────────────────────────────────────────────

class IsClientUser(BasePermission):
    """
    Grants access only to authenticated, active, non-deleted CLIENT users.

    Checks
    ------
    - is_authenticated  → valid JWT carried in the request
    - role == 'client'  → not an admin sneaking through the API
    - is_active         → account has not been deactivated
    - deleted_at is None→ account has not been soft-deleted
    - not is_locked     → account is not temporarily locked
    """

    message = "Access restricted to active client accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return _is_live_user(user) and user.role == "client"


class IsClientUserOrReadOnly(BasePermission):
    """
    SAFE methods (GET, HEAD, OPTIONS) → any authenticated user.
    Write methods (POST, PUT, PATCH, DELETE) → active CLIENT only.
    """

    message = "Write access restricted to active client accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        if request.method in SAFE_METHODS:
            return bool(request.user and request.user.is_authenticated)
        user = request.user
        return _is_live_user(user) and user.role == "client"


# ──────────────────────────────────────────────────────────────────────────────
# 2. ADMIN
# ──────────────────────────────────────────────────────────────────────────────

class IsAdminUser(BasePermission):
    """
    Grants access only to ADMIN (or SUPERADMIN) users.
    Admins can manage their own tenant; superadmins can manage everything.
    """

    message = "Access restricted to admin accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return _is_live_user(user) and user.role in ("admin", "superadmin")


class IsAdminOrReadOnly(BasePermission):
    """
    SAFE methods → any authenticated user.
    Write methods → ADMIN / SUPERADMIN only.
    """

    message = "Write access restricted to admin accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        if request.method in SAFE_METHODS:
            return bool(request.user and request.user.is_authenticated)
        user = request.user
        return _is_live_user(user) and user.role in ("admin", "superadmin")


# ──────────────────────────────────────────────────────────────────────────────
# 3. SUPER ADMIN
# ──────────────────────────────────────────────────────────────────────────────

class IsSuperAdmin(BasePermission):
    """
    Grants access only to SUPERADMIN users (cross-tenant operations,
    system configuration, etc.).
    """

    message = "Access restricted to super-admin accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return _is_live_user(user) and user.role == "superadmin"


# ──────────────────────────────────────────────────────────────────────────────
# 4. SAME TENANT
# ──────────────────────────────────────────────────────────────────────────────

class IsSameTenant(BasePermission):
    """
    Object-level permission that ensures the requesting user belongs to the
    same tenant as the target object.

    The target object must expose a `tenant` attribute (FK or direct field).
    Superadmins bypass the tenant check entirely.

    Usage
    -----
    permission_classes = [IsAuthenticated, IsSameTenant]
    """

    message = "You do not have access to resources from another tenant."

    def has_object_permission(self, request: Request, view: APIView, obj) -> bool:
        user = request.user
        if not _is_live_user(user):
            return False
        # Superadmins are unrestricted
        if user.role == "superadmin" or user.is_superuser:
            return True
        # Compare tenant FK
        obj_tenant = getattr(obj, "tenant", None)
        if obj_tenant is None:
            # Object has no tenant — allow if user has no tenant (global object)
            return user.tenant is None
        return obj_tenant == user.tenant


# ──────────────────────────────────────────────────────────────────────────────
# 5. OBJECT OWNER
# ──────────────────────────────────────────────────────────────────────────────

class IsOwnerOrAdmin(BasePermission):
    """
    Object-level permission.
    Grants access when the requesting user IS the object owner, OR has an
    admin / superadmin role.

    The target object must expose a `user` attribute pointing to the User FK.
    """

    message = "You do not have permission to access this resource."

    def has_object_permission(self, request: Request, view: APIView, obj) -> bool:
        user = request.user
        if not _is_live_user(user):
            return False
        if user.role in ("admin", "superadmin") or user.is_superuser:
            return True
        obj_user = getattr(obj, "user", None)
        return obj_user is not None and obj_user == user


# ──────────────────────────────────────────────────────────────────────────────
# 6. EMAIL VERIFIED
# ──────────────────────────────────────────────────────────────────────────────

class IsEmailVerified(BasePermission):
    """
    Requires the user to have verified their email address.
    Combine with any role permission.
    """

    message = "Please verify your email address before accessing this resource."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and getattr(user, "is_email_verified", False)
        )


# ──────────────────────────────────────────────────────────────────────────────
# 7. RBAC CODENAME
# ──────────────────────────────────────────────────────────────────────────────

class HasRBACPermission(BasePermission):
    """
    Checks the RBAC system for a specific permission codename.

    Usage
    -----
    class MyView(APIView):
        permission_classes = [IsAuthenticated, HasRBACPermission]
        required_permission = "invoice:approve"
    """

    message = "You do not have the required permission."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        if not _is_live_user(user):
            return False
        if user.is_superuser:
            return True
        codename = getattr(view, "required_permission", None)
        if not codename:
            # No codename declared → allow (use a role permission for that)
            return True
        return user._has_rbac_perm(codename)