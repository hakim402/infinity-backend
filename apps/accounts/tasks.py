from __future__ import annotations

import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger("apps.accounts")


@shared_task(name="apps.accounts.tasks.cleanup_expired_tokens")
def cleanup_expired_tokens() -> dict:
    from .models import EmailVerificationToken, MagicLinkToken, PasswordResetToken, UserRefreshToken

    now = timezone.now()
    ml_deleted, _ = MagicLinkToken.objects.filter(expires_at__lt=now).delete()
    ev_deleted, _ = EmailVerificationToken.objects.filter(expires_at__lt=now).delete()
    pr_deleted, _ = PasswordResetToken.objects.filter(expires_at__lt=now).delete()
    rf_deleted, _ = UserRefreshToken.objects.filter(expires_at__lt=now).delete()

    summary = {
        "magic_link_tokens_deleted": ml_deleted,
        "email_verification_tokens_deleted": ev_deleted,
        "password_reset_tokens_deleted": pr_deleted,
        "refresh_tokens_deleted": rf_deleted,
    }
    logger.info("cleanup_expired_tokens: %s", summary)
    return summary


@shared_task(name="apps.accounts.tasks.unlock_expired_accounts")
def unlock_expired_accounts() -> int:
    from .models import User

    count = User.objects.filter(
        locked_until__lt=timezone.now(),
        locked_until__isnull=False,
    ).update(locked_until=None, failed_login_attempts=0)

    if count:
        logger.info("unlock_expired_accounts: unlocked %d accounts", count)
    return count
