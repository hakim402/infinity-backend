from __future__ import annotations

from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView


def _is_live_user(user) -> bool:
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and user.deleted_at is None
        and not user.is_locked
    )


class IsClientUser(BasePermission):
    message = "Access restricted to active client accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return _is_live_user(user) and user.role == "client"


class IsClientUserOrReadOnly(BasePermission):
    message = "Write access restricted to active client accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        if request.method in SAFE_METHODS:
            return bool(request.user and request.user.is_authenticated)
        user = request.user
        return _is_live_user(user) and user.role == "client"


class IsAdminUser(BasePermission):
    message = "Access restricted to admin accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return _is_live_user(user) and user.role in ("admin", "superadmin")


class IsAdminOrReadOnly(BasePermission):
    message = "Write access restricted to admin accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        if request.method in SAFE_METHODS:
            return bool(request.user and request.user.is_authenticated)
        user = request.user
        return _is_live_user(user) and user.role in ("admin", "superadmin")


class IsSuperAdmin(BasePermission):
    message = "Access restricted to super-admin accounts."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return _is_live_user(user) and user.role == "superadmin"


class IsSameTenant(BasePermission):
    message = "You do not have access to resources from another tenant."

    def has_object_permission(self, request: Request, view: APIView, obj) -> bool:
        user = request.user
        if not _is_live_user(user):
            return False
        if user.role == "superadmin" or user.is_superuser:
            return True
        obj_tenant = getattr(obj, "tenant", None)
        if obj_tenant is None:
            return user.tenant is None
        return obj_tenant == user.tenant


class IsOwnerOrAdmin(BasePermission):
    message = "You do not have permission to access this resource."

    def has_object_permission(self, request: Request, view: APIView, obj) -> bool:
        user = request.user
        if not _is_live_user(user):
            return False
        if user.role in ("admin", "superadmin") or user.is_superuser:
            return True
        obj_user = getattr(obj, "user", None)
        return obj_user is not None and obj_user == user


class IsEmailVerified(BasePermission):
    message = "Please verify your email address before accessing this resource."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        return bool(user and user.is_authenticated and getattr(user, "is_email_verified", False))


class HasRBACPermission(BasePermission):
    message = "You do not have the required permission."

    def has_permission(self, request: Request, view: APIView) -> bool:
        user = request.user
        if not _is_live_user(user):
            return False
        if user.is_superuser:
            return True
        codename = getattr(view, "required_permission", None)
        if not codename:
            return True
        return user._has_rbac_perm(codename)
