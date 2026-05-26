"""
apps/accounts/admin.py
───────────────────────
Unfold-compatible admin registration for all accounts models.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from unfold.admin import ModelAdmin, TabularInline

from .models import (
    EmailVerificationToken,
    MagicLinkToken,
    PasswordResetToken,
    Permission,
    Role,
    Tenant,
    User,
    UserMFA,
    UserProfile,
    UserRefreshToken,
    UserRoleAssignment,
)


# ──────────────────────────────────────────────────────────────────────────────
# INLINES
# ──────────────────────────────────────────────────────────────────────────────

class UserProfileInline(TabularInline):
    model       = UserProfile
    extra       = 0
    can_delete  = False
    verbose_name_plural = _("Profile")
    fields = [
        "phone_number", "date_of_birth",
        "city", "country", "timezone", "language",
    ]

class UserRoleAssignmentInline(TabularInline):
    model   = UserRoleAssignment
    fk_name = "user"
    extra   = 0
    fields  = ["role", "assigned_at", "expires_at", "assigned_by"]
    readonly_fields = ["assigned_at"]


class UserRefreshTokenInline(TabularInline):
    model         = UserRefreshToken
    extra         = 0
    can_delete    = False
    readonly_fields = [
        "jti", "device_name", "ip_address",
        "revoked", "last_used_at", "created_at", "expires_at",
    ]
    max_num = 10


# ──────────────────────────────────────────────────────────────────────────────
# TENANT
# ──────────────────────────────────────────────────────────────────────────────

@admin.register(Tenant)
class TenantAdmin(ModelAdmin):
    list_display  = ["name", "slug", "subscription_tier", "is_active", "created_at"]
    list_filter   = ["subscription_tier", "is_active"]
    search_fields = ["name", "slug"]
    readonly_fields = ["id", "created_at", "updated_at"]
    prepopulated_fields = {"slug": ("name",)}


# ──────────────────────────────────────────────────────────────────────────────
# USER
# ──────────────────────────────────────────────────────────────────────────────

@admin.register(User)
class UserAdmin(ModelAdmin):
    list_display  = [
        "email", "full_name", "role", "tenant",
        "is_active", "is_email_verified", "is_locked", "created_at",
    ]
    list_filter   = ["role", "is_active", "is_email_verified", "is_staff", "is_superuser"]
    search_fields = ["email", "full_name"]
    readonly_fields = [
        "id", "created_at", "last_login_ip",
        "failed_login_attempts", "locked_until",
        "password_last_changed", "deleted_at",
        "google_sub",
    ]
    ordering      = ["-created_at"]
    inlines       = [UserProfileInline, UserRoleAssignmentInline, UserRefreshTokenInline]

    fieldsets = (
        (_("Identity"), {
            "fields": ("id", "email", "full_name", "role", "tenant"),
        }),
        (_("Auth"), {
            "fields": ("password",),
        }),
        (_("Google OAuth"), {
            "fields": ("google_sub", "google_picture_url"),
            "classes": ("collapse",),
        }),
        (_("Permissions"), {
            "fields": ("is_active", "is_staff", "is_superuser", "is_email_verified"),
        }),
        (_("Security"), {
            "fields": (
                "last_login_ip", "failed_login_attempts",
                "locked_until", "password_last_changed",
            ),
            "classes": ("collapse",),
        }),
        (_("Legal"), {
            "fields": ("terms_accepted_at", "privacy_accepted_version"),
            "classes": ("collapse",),
        }),
        (_("Audit"), {
            "fields": ("created_at", "created_by", "deleted_at", "deleted_by"),
            "classes": ("collapse",),
        }),
    )

    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "full_name", "role", "tenant", "password1", "password2"),
        }),
    )


# ──────────────────────────────────────────────────────────────────────────────
# RBAC
# ──────────────────────────────────────────────────────────────────────────────

@admin.register(Permission)
class PermissionAdmin(ModelAdmin):
    list_display  = ["codename", "name", "resource_type"]
    search_fields = ["codename", "name", "resource_type"]
    list_filter   = ["resource_type"]


@admin.register(Role)
class RoleAdmin(ModelAdmin):
    list_display  = ["name", "created_at"]
    search_fields = ["name"]
    filter_horizontal = ["permissions"]


@admin.register(UserRoleAssignment)
class UserRoleAssignmentAdmin(ModelAdmin):
    list_display  = ["user", "role", "is_active", "assigned_at", "expires_at"]
    list_filter   = ["role"]
    search_fields = ["user__email", "role__name"]
    readonly_fields = ["assigned_at"]


# ──────────────────────────────────────────────────────────────────────────────
# SESSIONS
# ──────────────────────────────────────────────────────────────────────────────

@admin.register(UserRefreshToken)
class UserRefreshTokenAdmin(ModelAdmin):
    list_display  = [
        "user", "device_name", "ip_address",
        "revoked", "last_used_at", "expires_at",
    ]
    list_filter   = ["revoked"]
    search_fields = ["user__email", "device_name", "ip_address"]
    readonly_fields = [
        "id", "jti", "user", "device_name", "ip_address",
        "user_agent", "last_used_at", "created_at",
    ]

    def has_add_permission(self, request):
        return False


# ──────────────────────────────────────────────────────────────────────────────
# TOKENS
# ──────────────────────────────────────────────────────────────────────────────

class _BaseTokenAdmin(ModelAdmin):
    list_display    = ["user", "is_valid", "used", "expires_at", "created_at"]
    readonly_fields = ["id", "token_hash", "user", "used", "used_at", "created_at"]
    list_filter     = ["used"]
    search_fields   = ["user__email"]

    def has_add_permission(self, request):
        return False


@admin.register(MagicLinkToken)
class MagicLinkTokenAdmin(_BaseTokenAdmin):
    pass


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(_BaseTokenAdmin):
    pass


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(_BaseTokenAdmin):
    pass


# ──────────────────────────────────────────────────────────────────────────────
# MFA
# ──────────────────────────────────────────────────────────────────────────────

@admin.register(UserMFA)
class UserMFAAdmin(ModelAdmin):
    list_display  = ["user", "method", "is_active", "created_at"]
    list_filter   = ["method", "is_active"]
    search_fields = ["user__email"]
    readonly_fields = ["id", "user", "secret_encrypted", "created_at", "updated_at"]