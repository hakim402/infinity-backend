from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta

from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import (
    EmailVerificationToken,
    MagicLinkToken,
    PasswordResetToken,
    Permission,
    Role,
    Tenant,
    User,
    UserRefreshToken,
)


TEST_PASSWORD = "StrongPass123!"


def sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_tenant(**kwargs) -> Tenant:
    defaults = {
        "name": "Test Tenant",
        "slug": f"test-tenant-{secrets.token_hex(4)}",
    }
    defaults.update(kwargs)
    return Tenant.objects.create(**defaults)


def create_user(
    *,
    email: str | None = None,
    password: str = TEST_PASSWORD,
    full_name: str = "Test User",
    role: str = User.Role.CLIENT,
    tenant: Tenant | None = None,
    is_email_verified: bool = True,
    is_active: bool = True,
    is_staff: bool = False,
    is_superuser: bool = False,
    **extra,
) -> User:
    email = email or f"user-{secrets.token_hex(4)}@example.com"
    user = User.objects.create_user(
        email=email,
        full_name=full_name,
        password=password,
        role=role,
        tenant=tenant,
        is_email_verified=is_email_verified,
        is_active=is_active,
        is_staff=is_staff,
        is_superuser=is_superuser,
        **extra,
    )
    return user


def create_admin(**kwargs) -> User:
    kwargs.setdefault("role", User.Role.ADMIN)
    kwargs.setdefault("is_staff", True)
    return create_user(**kwargs)


def create_superadmin(**kwargs) -> User:
    kwargs.setdefault("role", User.Role.SUPERADMIN)
    kwargs.setdefault("is_staff", True)
    kwargs.setdefault("is_superuser", True)
    kwargs.setdefault("is_email_verified", True)
    return create_user(**kwargs)


def create_email_verification_token(
    user: User,
    *,
    raw_token: str = "email-verify-token",
    expires_delta: timedelta = timedelta(hours=1),
    used: bool = False,
) -> tuple[EmailVerificationToken, str]:
    token = EmailVerificationToken.objects.create(
        user=user,
        token_hash=sha256(raw_token),
        expires_at=timezone.now() + expires_delta,
        used=used,
    )
    return token, raw_token


def create_magic_link_token(
    user: User,
    *,
    raw_token: str = "magic-link-token",
    expires_delta: timedelta = timedelta(minutes=15),
    used: bool = False,
) -> tuple[MagicLinkToken, str]:
    token = MagicLinkToken.objects.create(
        user=user,
        token_hash=sha256(raw_token),
        expires_at=timezone.now() + expires_delta,
        used=used,
    )
    return token, raw_token


def create_password_reset_token(
    user: User,
    *,
    raw_token: str = "password-reset-token",
    expires_delta: timedelta = timedelta(minutes=30),
    used: bool = False,
) -> tuple[PasswordResetToken, str]:
    token = PasswordResetToken.objects.create(
        user=user,
        token_hash=sha256(raw_token),
        expires_at=timezone.now() + expires_delta,
        used=used,
    )
    return token, raw_token


def create_refresh_session(
    user: User,
    *,
    revoked: bool = False,
    expires_delta: timedelta = timedelta(days=1),
    device_name: str = "Chrome Browser",
) -> tuple[UserRefreshToken, str]:
    refresh = RefreshToken.for_user(user)
    session = UserRefreshToken.objects.create(
        user=user,
        jti=str(refresh["jti"]),
        expires_at=timezone.now() + expires_delta,
        revoked=revoked,
        device_name=device_name,
        ip_address="127.0.0.1",
        user_agent="Mozilla/5.0 Chrome",
    )
    return session, str(refresh)


def create_rbac_permission(codename: str = "invoice:approve") -> Permission:
    return Permission.objects.create(
        codename=codename,
        name=codename.replace(":", " ").title(),
        resource_type=codename.split(":")[0],
    )


def assign_role_with_permission(user: User, codename: str = "invoice:approve") -> Role:
    permission = create_rbac_permission(codename)
    role = Role.objects.create(name=f"Role {secrets.token_hex(3)}")
    role.permissions.add(permission)
    user.roles.add(role)
    return role
