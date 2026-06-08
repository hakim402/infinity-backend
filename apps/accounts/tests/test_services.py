from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

import pytest
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.test import APIRequestFactory
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import (
    EmailVerificationToken,
    MagicLinkToken,
    PasswordResetToken,
    User,
    UserRefreshToken,
)
from apps.accounts.services.services import AuthService
from .factories import (
    TEST_PASSWORD,
    create_email_verification_token,
    create_magic_link_token,
    create_password_reset_token,
    create_refresh_session,
    create_user,
)


pytestmark = pytest.mark.django_db


def make_request():
    return APIRequestFactory().post(
        "/",
        HTTP_USER_AGENT="Mozilla/5.0 Chrome",
        REMOTE_ADDR="127.0.0.1",
    )


@patch("apps.accounts.services.services._send_email")
def test_register_creates_user_and_email_verification_token(mock_send_email, settings):
    settings.EMAIL_VERIFICATION_EXPIRY_HOURS = 24
    user = AuthService.register(
        {
            "email": "service-register@example.com",
            "full_name": "Service User",
            "password": TEST_PASSWORD,
            "terms_accepted": True,
        }
    )

    assert user.email == "service-register@example.com"
    assert user.check_password(TEST_PASSWORD)
    assert user.role == User.Role.CLIENT
    assert user.terms_accepted_at is not None
    assert EmailVerificationToken.objects.filter(user=user).count() == 1
    mock_send_email.assert_called_once()


def test_register_rejects_weak_password():
    with pytest.raises(ValidationError):
        AuthService.register(
            {
                "email": "weak@example.com",
                "full_name": "Weak User",
                "password": "123",
                "terms_accepted": True,
            }
        )


def test_verify_email_consumes_token_and_marks_user_verified():
    user = create_user(is_email_verified=False)
    token, _ = create_email_verification_token(user)

    AuthService.verify_email(token)

    token.refresh_from_db()
    user.refresh_from_db()

    assert token.used is True
    assert user.is_email_verified is True


def test_login_issues_tokens_records_session_and_resets_failed_attempts():
    user = create_user(password=TEST_PASSWORD)
    user.failed_login_attempts = 3
    user.save(update_fields=["failed_login_attempts"])

    tokens = AuthService.login(user, make_request())

    user.refresh_from_db()

    assert "access" in tokens
    assert "refresh" in tokens
    assert UserRefreshToken.objects.filter(user=user, revoked=False).count() == 1
    assert user.failed_login_attempts == 0
    assert user.last_login_ip == "127.0.0.1"


@patch("apps.accounts.services.services._send_email")
def test_magic_link_request_creates_token_for_existing_user(mock_send_email, settings):
    settings.MAGIC_LINK_EXPIRY_MINUTES = 15
    settings.FRONTEND_BASE_URL = "https://frontend.test"
    user = create_user(email="magic@example.com")

    AuthService.magic_link_request("magic@example.com")

    assert MagicLinkToken.objects.filter(user=user, used=False).count() == 1
    mock_send_email.assert_called_once()


@patch("apps.accounts.services.services._send_email")
def test_magic_link_request_silently_ignores_unknown_email(mock_send_email):
    AuthService.magic_link_request("missing@example.com")

    assert MagicLinkToken.objects.count() == 0
    mock_send_email.assert_not_called()


def test_magic_link_verify_consumes_token_auto_verifies_email_and_issues_session():
    user = create_user(is_email_verified=False)
    token, _ = create_magic_link_token(user)

    tokens = AuthService.magic_link_verify(token, make_request())

    token.refresh_from_db()
    user.refresh_from_db()

    assert "access" in tokens
    assert "refresh" in tokens
    assert token.used is True
    assert user.is_email_verified is True
    assert UserRefreshToken.objects.filter(user=user, revoked=False).exists()


@patch("apps.accounts.services.services._send_email")
def test_password_reset_request_creates_token_for_existing_user(mock_send_email, settings):
    settings.PASSWORD_RESET_EXPIRY_MINUTES = 30
    settings.FRONTEND_BASE_URL = "https://frontend.test"
    user = create_user(email="reset@example.com")

    AuthService.password_reset_request("reset@example.com")

    assert PasswordResetToken.objects.filter(user=user, used=False).count() == 1
    mock_send_email.assert_called_once()


def test_password_reset_confirm_changes_password_consumes_token_and_revokes_sessions():
    user = create_user(password=TEST_PASSWORD)
    create_refresh_session(user)
    token, _ = create_password_reset_token(user)

    AuthService.password_reset_confirm(token, "NewStrongPass123!")

    token.refresh_from_db()
    user.refresh_from_db()

    assert token.used is True
    assert user.check_password("NewStrongPass123!")
    assert user.password_last_changed is not None
    assert UserRefreshToken.objects.filter(user=user, revoked=False).count() == 0


def test_refresh_token_rotates_session():
    user = create_user()
    old_session, refresh = create_refresh_session(user)

    tokens = AuthService.refresh_token(refresh, make_request())

    old_session.refresh_from_db()

    assert old_session.revoked is True
    assert "access" in tokens
    assert "refresh" in tokens
    assert UserRefreshToken.objects.filter(user=user, revoked=False).count() == 1


def test_refresh_token_reuse_revokes_all_sessions_and_raises():
    user = create_user()
    session, refresh = create_refresh_session(user, revoked=True)
    create_refresh_session(user, device_name="Other Device")

    with pytest.raises(AuthenticationFailed):
        AuthService.refresh_token(refresh, make_request())

    assert UserRefreshToken.objects.filter(user=user, revoked=False).count() == 1


def test_refresh_token_missing_session_raises():
    user = create_user()
    refresh = str(RefreshToken.for_user(user))

    with pytest.raises(AuthenticationFailed):
        AuthService.refresh_token(refresh, make_request())


def test_logout_revokes_matching_session():
    user = create_user()
    session, refresh = create_refresh_session(user)

    AuthService.logout(refresh, user)

    session.refresh_from_db()
    assert session.revoked is True


def test_change_password_changes_password_and_revokes_other_sessions():
    user = create_user(password=TEST_PASSWORD)
    preserved_session, current_refresh = create_refresh_session(user, device_name="Current")
    other_session, _ = create_refresh_session(user, device_name="Other")

    AuthService.change_password(
        user,
        "NewStrongPass123!",
        current_refresh=current_refresh,
    )

    user.refresh_from_db()
    preserved_session.refresh_from_db()
    other_session.refresh_from_db()

    assert user.check_password("NewStrongPass123!")
    assert user.password_last_changed is not None
    assert preserved_session.revoked is False
    assert other_session.revoked is True
