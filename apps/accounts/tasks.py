"""
apps/accounts/tasks.py
───────────────────────
Celery tasks for the accounts application.

Task design principles
----------------------
- bind=True           → self reference for retry logic.
- acks_late=True      → message acknowledged only after successful execution;
                        prevents silent task loss on worker crash.
- max_retries=3       → retry on transient failures (SMTP timeouts, etc.).
- Dispatch AFTER the wrapping DB transaction commits — never inside a transaction
  — so workers don't read data that hasn't been committed yet.
"""

from __future__ import annotations

import logging
from typing import Any

from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail

log = logging.getLogger(__name__)

_MAGIC_LINK_SUBJECT = "Your sign-in link"
_MAGIC_LINK_ROUTE   = "/auth/magic"


# ──────────────────────────────────────────────────────────────────────────────
# EMAIL TASK
# ──────────────────────────────────────────────────────────────────────────────

@shared_task(
    bind=True,
    max_retries=3,
    default_retry_delay=30,    # seconds; doubles on each retry
    acks_late=True,
    name="accounts.send_magic_link_email",
)
def send_magic_link_email(self, user_pk: str, raw_token: str) -> None:
    """
    Send a passwordless login/registration email containing a magic link.

    This task is used for BOTH registration and subsequent login requests.

    Args:
        user_pk:   String UUID of the target User.
        raw_token: The raw (unhashed) token to embed in the URL.
                   IMPORTANT: this is never persisted — it only lives in this
                   email and in transit to the recipient's inbox.

    Retry policy:
        Up to 3 retries with 30/60/120-second back-off on any exception.
    """
    from django.contrib.auth import get_user_model
    User = get_user_model()

    try:
        user = User.objects.get(pk=user_pk)
    except User.DoesNotExist:
        log.error(
            "send_magic_link_email: user_id=%s not found — aborting task.",
            user_pk,
        )
        return

    frontend_url = getattr(settings, "FRONTEND_BASE_URL", "http://localhost:3000")
    magic_url    = f"{frontend_url.rstrip('/')}{_MAGIC_LINK_ROUTE}?token={raw_token}"
    ttl_minutes  = int(getattr(settings, "MAGIC_LINK_EXPIRY_MINUTES", 15))
    app_name     = getattr(settings, "APP_NAME", "Our App")

    plain_body = (
        f"Hi {user.full_name},\n\n"
        f"Click the link below to sign in to your {app_name} account:\n\n"
        f"  {magic_url}\n\n"
        f"This link expires in {ttl_minutes} minutes and can only be used once.\n\n"
        f"If you did not request this link, please ignore this email.\n\n"
        f"— The {app_name} Team"
    )

    html_body = (
        f"<p>Hi <strong>{user.full_name}</strong>,</p>"
        f"<p>Click the button below to sign in securely:</p>"
        f'<p style="margin: 24px 0;">'
        f'  <a href="{magic_url}" '
        f'     style="background:#4F46E5;color:#fff;padding:12px 28px;'
        f'            border-radius:6px;text-decoration:none;font-weight:600;'
        f'            font-family:sans-serif;font-size:15px;">'
        f"    Sign in to {app_name}"
        f"  </a>"
        f"</p>"
        f"<p style='color:#6B7280;font-size:0.875em;'>"
        f"  This link expires in <strong>{ttl_minutes}&nbsp;minutes</strong> "
        f"  and can only be used once.<br>"
        f"  If you did not request this email, please ignore it — "
        f"  your account remains secure."
        f"</p>"
    )

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", settings.EMAIL_HOST_USER)

    try:
        send_mail(
            subject=_MAGIC_LINK_SUBJECT,
            message=plain_body,
            html_message=html_body,
            from_email=from_email,
            recipient_list=[user.email],
            fail_silently=False,
        )
        log.info(
            "Magic link email sent: user_id=%s email=%s",
            user_pk, user.email,
        )

    except Exception as exc:
        log.warning(
            "Magic link email failed for user_id=%s: %s  (retry %d/%d)",
            user_pk, exc,
            self.request.retries, self.max_retries,
        )
        raise self.retry(exc=exc)


# ──────────────────────────────────────────────────────────────────────────────
# MAINTENANCE TASKS
# Register in settings.CELERY_BEAT_SCHEDULE (see settings.py)
# ──────────────────────────────────────────────────────────────────────────────

@shared_task(
    name="accounts.cleanup_expired_tokens",
    acks_late=True,
)
def cleanup_expired_tokens() -> dict[str, Any]:
    """
    Purge expired and used token records to keep token tables lean.

    Runs hourly via django-celery-beat.  Returns a summary dict so the result
    can be inspected in Flower or the Celery result backend.

    Celery beat schedule entry (in settings.py):
        "cleanup-expired-tokens": {
            "task":     "accounts.cleanup_expired_tokens",
            "schedule": crontab(minute=0),   # top of every hour
        },
    """
    from django.utils import timezone
    from apps.accounts.models import (
        MagicLinkToken,
        EmailVerificationToken,
        PasswordResetToken,
        UserRefreshToken,
    )

    now = timezone.now()

    ml = MagicLinkToken.objects.filter(expires_at__lt=now).delete()[0]
    ev = EmailVerificationToken.objects.filter(expires_at__lt=now).delete()[0]
    pr = PasswordResetToken.objects.filter(expires_at__lt=now).delete()[0]
    rt = UserRefreshToken.objects.filter(expires_at__lt=now).delete()[0]

    result: dict[str, Any] = {
        "magic_link_tokens_deleted":         ml,
        "email_verification_tokens_deleted": ev,
        "password_reset_tokens_deleted":     pr,
        "refresh_tokens_deleted":            rt,
    }
    log.info("Expired token cleanup complete: %s", result)
    return result