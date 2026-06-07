from __future__ import annotations

from datetime import timedelta

import pytest
from django.db import IntegrityError
from django.utils import timezone

from apps.accounts.models import (
    EmailVerificationToken,
    MagicLinkToken,
    Tenant,
    User,
    UserMFA,
    UserProfile,
    UserRefreshToken,
)
from .factories import (
    TEST_PASSWORD,
    assign_role_with_permission,
    create_email_verification_token,
    create_refresh_session,
    create_tenant,
    create_user,
)


pytestmark = pytest.mark.django_db


def test_create_user_normalizes_email_and_hashes_password():
    user = create_user(email="TEST@Example.COM", password=TEST_PASSWORD)

    assert user.email == "test@example.com"
    assert user.check_password(TEST_PASSWORD)
    assert user.role == User.Role.CLIENT
    assert user.is_active is True


def test_user_profile_is_auto_created_on_user_creation():
    user = create_user()

    assert UserProfile.objects.filter(user=user).exists()
    assert user.profile.user == user


def test_create_superuser_flags_are_valid():
    user = User.objects.create_superuser(
        email="root@example.com",
        full_name="Root User",
        password=TEST_PASSWORD,
    )

    assert user.is_staff is True
    assert user.is_superuser is True
    assert user.is_email_verified is True


def test_create_superuser_requires_staff_true():
    with pytest.raises(ValueError):
        User.objects.create_superuser(
            email="bad@example.com",
            full_name="Bad User",
            password=TEST_PASSWORD,
            is_staff=False,
        )


def test_soft_delete_deactivates_and_obfuscates_email_so_email_can_be_reused():
    user = create_user(email="reuse@example.com")
    user.soft_delete()

    user.refresh_from_db()
    assert user.is_active is False
    assert user.deleted_at is not None
    assert user.email.startswith(f"deleted_{user.id}_")

    new_user = create_user(email="reuse@example.com")
    assert new_user.email == "reuse@example.com"


def test_email_is_globally_unique_for_active_rows():
    create_user(email="unique@example.com")

    with pytest.raises(IntegrityError):
        create_user(email="unique@example.com")


def test_is_locked_property():
    user = create_user()
    assert user.is_locked is False

    user.locked_until = timezone.now() + timedelta(minutes=5)
    user.save(update_fields=["locked_until"])
    assert user.is_locked is True

    user.locked_until = timezone.now() - timedelta(minutes=5)
    user.save(update_fields=["locked_until"])
    assert user.is_locked is False


def test_failed_login_helpers():
    user = create_user()
    user.increment_failed_login()
    user.refresh_from_db()

    assert user.failed_login_attempts == 1

    user.lock_account(timezone.now() + timedelta(minutes=10))
    user.reset_failed_login()
    user.refresh_from_db()

    assert user.failed_login_attempts == 0
    assert user.locked_until is None


def test_token_validity_and_consume():
    user = create_user()
    token, _ = create_email_verification_token(user)

    assert token.is_valid is True

    token.consume()
    token.refresh_from_db()

    assert token.used is True
    assert token.used_at is not None
    assert token.is_valid is False


def test_expired_token_is_invalid_and_cannot_be_consumed():
    user = create_user()
    token, _ = create_email_verification_token(
        user,
        raw_token="expired",
        expires_delta=timedelta(minutes=-1),
    )

    assert token.is_valid is False
    with pytest.raises(ValueError):
        token.consume()


def test_refresh_token_revoke_marks_session_revoked():
    user = create_user()
    session, _ = create_refresh_session(user)

    session.revoke()
    session.refresh_from_db()

    assert session.revoked is True


def test_user_has_rbac_permission_when_assigned_active_role():
    user = create_user()
    assign_role_with_permission(user, "invoice:approve")

    assert user._has_rbac_perm("invoice:approve") is True
    assert user.has_perm("invoice:approve") is True


def test_user_does_not_have_unknown_rbac_permission():
    user = create_user()

    assert user._has_rbac_perm("invoice:approve") is False


def test_tenant_string():
    tenant = create_tenant(name="Acme", slug="acme")
    assert "Acme" in str(tenant)


def test_one_active_mfa_per_user_constraint():
    user = create_user()
    UserMFA.objects.create(
        user=user,
        method=UserMFA.Method.TOTP,
        secret_encrypted="secret-1",
        is_active=True,
    )

    with pytest.raises(IntegrityError):
        UserMFA.objects.create(
            user=user,
            method=UserMFA.Method.WEBAUTHN,
            secret_encrypted="secret-2",
            is_active=True,
        )
