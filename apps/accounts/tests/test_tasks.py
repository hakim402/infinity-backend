from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.accounts.models import (
    EmailVerificationToken,
    MagicLinkToken,
    PasswordResetToken,
    UserRefreshToken,
)
from apps.accounts.tasks import cleanup_expired_tokens, unlock_expired_accounts
from .factories import (
    create_email_verification_token,
    create_magic_link_token,
    create_password_reset_token,
    create_refresh_session,
    create_user,
)


pytestmark = pytest.mark.django_db


def test_cleanup_expired_tokens_deletes_only_expired_tokens():
    user = create_user()

    create_magic_link_token(user, raw_token="expired-ml", expires_delta=timedelta(minutes=-1))
    create_email_verification_token(user, raw_token="expired-ev", expires_delta=timedelta(minutes=-1))
    create_password_reset_token(user, raw_token="expired-pr", expires_delta=timedelta(minutes=-1))
    create_refresh_session(user, expires_delta=timedelta(minutes=-1))

    create_magic_link_token(user, raw_token="valid-ml", expires_delta=timedelta(minutes=5))
    create_email_verification_token(user, raw_token="valid-ev", expires_delta=timedelta(minutes=5))
    create_password_reset_token(user, raw_token="valid-pr", expires_delta=timedelta(minutes=5))
    create_refresh_session(user, expires_delta=timedelta(minutes=5))

    summary = cleanup_expired_tokens()

    assert summary["magic_link_tokens_deleted"] == 1
    assert summary["email_verification_tokens_deleted"] == 1
    assert summary["password_reset_tokens_deleted"] == 1
    assert summary["refresh_tokens_deleted"] == 1

    assert MagicLinkToken.objects.count() == 1
    assert EmailVerificationToken.objects.count() == 1
    assert PasswordResetToken.objects.count() == 1
    assert UserRefreshToken.objects.count() == 1


def test_unlock_expired_accounts_unlocks_only_expired_locks():
    expired_locked_user = create_user(email="expired-lock@example.com")
    active_locked_user = create_user(email="active-lock@example.com")

    expired_locked_user.failed_login_attempts = 5
    expired_locked_user.locked_until = timezone.now() - timedelta(minutes=1)
    expired_locked_user.save(update_fields=["failed_login_attempts", "locked_until"])

    active_locked_user.failed_login_attempts = 5
    active_locked_user.locked_until = timezone.now() + timedelta(minutes=10)
    active_locked_user.save(update_fields=["failed_login_attempts", "locked_until"])

    count = unlock_expired_accounts()

    expired_locked_user.refresh_from_db()
    active_locked_user.refresh_from_db()

    assert count == 1
    assert expired_locked_user.locked_until is None
    assert expired_locked_user.failed_login_attempts == 0
    assert active_locked_user.locked_until is not None
    assert active_locked_user.failed_login_attempts == 5
