from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from django.utils import timezone
from rest_framework.test import APIRequestFactory

from apps.accounts.api.serializers import (
    ChangePasswordSerializer,
    EmailLoginSerializer,
    EmailVerifySerializer,
    MagicLinkRequestSerializer,
    MagicLinkVerifySerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    UserRegistrationSerializer,
    UserUpdateSerializer,
)
from apps.accounts.models import User
from .factories import (
    TEST_PASSWORD,
    create_email_verification_token,
    create_magic_link_token,
    create_password_reset_token,
    create_user,
)


pytestmark = pytest.mark.django_db


def test_registration_serializer_valid_data():
    serializer = UserRegistrationSerializer(
        data={
            "email": "NEW@Example.COM",
            "full_name": "New User",
            "password": TEST_PASSWORD,
            "password_confirm": TEST_PASSWORD,
            "terms_accepted": True,
        }
    )

    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["email"] == "new@example.com"


def test_registration_serializer_rejects_duplicate_email():
    create_user(email="duplicate@example.com")

    serializer = UserRegistrationSerializer(
        data={
            "email": "duplicate@example.com",
            "full_name": "New User",
            "password": TEST_PASSWORD,
            "password_confirm": TEST_PASSWORD,
            "terms_accepted": True,
        }
    )

    assert serializer.is_valid() is False
    assert "email" in serializer.errors


def test_registration_serializer_rejects_password_mismatch():
    serializer = UserRegistrationSerializer(
        data={
            "email": "new@example.com",
            "full_name": "New User",
            "password": TEST_PASSWORD,
            "password_confirm": "Different123!",
            "terms_accepted": True,
        }
    )

    assert serializer.is_valid() is False
    assert "password_confirm" in serializer.errors


def test_registration_serializer_requires_terms():
    serializer = UserRegistrationSerializer(
        data={
            "email": "new@example.com",
            "full_name": "New User",
            "password": TEST_PASSWORD,
            "password_confirm": TEST_PASSWORD,
            "terms_accepted": False,
        }
    )

    assert serializer.is_valid() is False
    assert "terms_accepted" in serializer.errors


def test_email_login_serializer_valid_credentials():
    user = create_user(email="login@example.com", password=TEST_PASSWORD, is_email_verified=True)

    serializer = EmailLoginSerializer(
        data={"email": "LOGIN@example.com", "password": TEST_PASSWORD}
    )

    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["user"] == user


def test_email_login_serializer_rejects_wrong_password_and_increments_attempts(settings):
    settings.MAX_FAILED_LOGIN_ATTEMPTS = 5
    user = create_user(email="wrong@example.com", password=TEST_PASSWORD, is_email_verified=True)

    serializer = EmailLoginSerializer(
        data={"email": "wrong@example.com", "password": "WrongPass123!"}
    )

    assert serializer.is_valid() is False
    user.refresh_from_db()
    assert user.failed_login_attempts == 1


def test_email_login_serializer_locks_after_max_failed_attempts(settings):
    settings.MAX_FAILED_LOGIN_ATTEMPTS = 1
    settings.ACCOUNT_LOCK_MINUTES = 30
    user = create_user(email="lock@example.com", password=TEST_PASSWORD, is_email_verified=True)

    serializer = EmailLoginSerializer(
        data={"email": "lock@example.com", "password": "WrongPass123!"}
    )

    assert serializer.is_valid() is False
    user.refresh_from_db()
    assert user.locked_until is not None
    assert user.is_locked is True


def test_email_login_serializer_rejects_unverified_user():
    create_user(email="unverified@example.com", password=TEST_PASSWORD, is_email_verified=False)

    serializer = EmailLoginSerializer(
        data={"email": "unverified@example.com", "password": TEST_PASSWORD}
    )

    assert serializer.is_valid() is False
    assert "non_field_errors" in serializer.errors


def test_email_verify_serializer_valid_token():
    user = create_user()
    _, raw_token = create_email_verification_token(user)

    serializer = EmailVerifySerializer(data={"token": raw_token}, context={})

    assert serializer.is_valid(), serializer.errors
    assert "ev_token" in serializer.context


def test_email_verify_serializer_rejects_expired_token():
    user = create_user()
    _, raw_token = create_email_verification_token(
        user,
        raw_token="expired-email",
        expires_delta=timedelta(minutes=-1),
    )

    serializer = EmailVerifySerializer(data={"token": raw_token}, context={})

    assert serializer.is_valid() is False
    assert "token" in serializer.errors


def test_magic_link_request_serializer_normalizes_email():
    serializer = MagicLinkRequestSerializer(data={"email": "USER@Example.COM"})

    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["email"] == "user@example.com"


def test_magic_link_verify_serializer_valid_token():
    user = create_user()
    _, raw_token = create_magic_link_token(user)

    serializer = MagicLinkVerifySerializer(data={"token": raw_token}, context={})

    assert serializer.is_valid(), serializer.errors
    assert "ml_token" in serializer.context


def test_password_reset_request_serializer_normalizes_email():
    serializer = PasswordResetRequestSerializer(data={"email": "USER@Example.COM"})

    assert serializer.is_valid(), serializer.errors
    assert serializer.validated_data["email"] == "user@example.com"


def test_password_reset_confirm_serializer_valid_token():
    user = create_user()
    _, raw_token = create_password_reset_token(user)

    serializer = PasswordResetConfirmSerializer(
        data={
            "token": raw_token,
            "password": "NewStrongPass123!",
            "password_confirm": "NewStrongPass123!",
        },
        context={},
    )

    assert serializer.is_valid(), serializer.errors
    assert "reset_token" in serializer.context


def test_password_reset_confirm_serializer_rejects_password_mismatch():
    serializer = PasswordResetConfirmSerializer(
        data={
            "token": "anything",
            "password": "NewStrongPass123!",
            "password_confirm": "DifferentStrongPass123!",
        },
        context={},
    )

    assert serializer.is_valid() is False
    assert "password_confirm" in serializer.errors


def test_user_update_serializer_updates_user_and_profile():
    user = create_user()
    serializer = UserUpdateSerializer(
        user,
        data={
            "full_name": "Updated Name",
            "profile": {
                "city": "Kabul",
                "country": "AF",
                "bio": "Updated bio",
            },
        },
        partial=True,
    )

    assert serializer.is_valid(), serializer.errors
    serializer.save()

    user.refresh_from_db()
    user.profile.refresh_from_db()

    assert user.full_name == "Updated Name"
    assert user.profile.city == "Kabul"
    assert user.profile.country == "AF"
    assert user.profile.bio == "Updated bio"


def test_change_password_serializer_valid_data():
    user = create_user(password=TEST_PASSWORD)
    request = APIRequestFactory().post("/")
    request.user = user

    serializer = ChangePasswordSerializer(
        data={
            "current_password": TEST_PASSWORD,
            "new_password": "NewStrongPass123!",
            "new_password_confirm": "NewStrongPass123!",
        },
        context={"request": request},
    )

    assert serializer.is_valid(), serializer.errors


def test_change_password_serializer_rejects_wrong_current_password():
    user = create_user(password=TEST_PASSWORD)
    request = APIRequestFactory().post("/")
    request.user = user

    serializer = ChangePasswordSerializer(
        data={
            "current_password": "WrongPass123!",
            "new_password": "NewStrongPass123!",
            "new_password_confirm": "NewStrongPass123!",
        },
        context={"request": request},
    )

    assert serializer.is_valid() is False
    assert "current_password" in serializer.errors
