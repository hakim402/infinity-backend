"""
apps/accounts/services/auth_service.py
───────────────────────────────────────
All authentication business logic lives here.
Views call these functions; nothing here knows about HTTP.

Public surface
--------------
  register_client(email, full_name)        → None   (sends magic link, returns nothing)
  request_magic_link(email)               → None   (fire-and-forget)
  verify_magic_link(raw_token, meta)      → dict   {access, refresh, user}
  refresh_access_token(raw_refresh, meta) → dict   {access, refresh, user}
  logout(user, raw_refresh, all_devices)  → None
  change_password(user, current, new)     → None
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta
from typing import TypedDict

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction, IntegrityError
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from apps.accounts.models import MagicLinkToken, UserRefreshToken

log = logging.getLogger(__name__)
User = get_user_model()


# ──────────────────────────────────────────────────────────────────────────────
# INTERNAL UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

def _sha256(value: str) -> str:
    """Return the hex-encoded SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _secure_compare(a: str, b: str) -> bool:
    """Constant-time string comparison — prevents timing-oracle attacks."""
    return hmac.compare_digest(a, b)


def _generate_raw_token() -> str:
    """Generate a cryptographically secure 48-character URL-safe token."""
    return secrets.token_urlsafe(48)


def _magic_link_ttl() -> datetime:
    """Return the expiry datetime for a new magic-link token."""
    minutes = int(getattr(settings, "MAGIC_LINK_EXPIRY_MINUTES", 15))
    return timezone.now() + timedelta(minutes=minutes)


def _parse_device_name(user_agent: str) -> str:
    """
    Lightweight UA parser — no third-party dependency.
    Returns a human-readable label like 'Chrome on Windows'.
    Replace with `ua-parser` / `user-agents` lib for production granularity.
    """
    ua = user_agent.lower()

    if "edg/" in ua:
        browser = "Edge"
    elif "opr/" in ua or "opera" in ua:
        browser = "Opera"
    elif "chrome" in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua:
        browser = "Safari"
    else:
        browser = "Browser"

    if "windows" in ua:
        os_ = "Windows"
    elif "android" in ua:
        os_ = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os_ = "iOS"
    elif "mac os" in ua or "macintosh" in ua:
        os_ = "macOS"
    elif "linux" in ua:
        os_ = "Linux"
    else:
        os_ = "Unknown OS"

    return f"{browser} on {os_}"


class _RequestMeta(TypedDict):
    """Carrier for HTTP-request metadata passed into service functions."""
    ip_address: str | None
    user_agent: str


# ──────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def register_client(email: str, full_name: str) -> None:
    """
    Register a new client user and send them a magic-link to verify their email
    and complete their first login in a single step.

    Behaviour
    ---------
    - Creates User with role=CLIENT, is_active=True, is_email_verified=False.
    - UserProfile is created automatically via the post_save signal — do NOT
      create it manually here.
    - Generates a MagicLinkToken (raw token → SHA-256 hash stored).
    - Dispatches send_magic_link_email Celery task (non-blocking).
    - The entire user + token creation is wrapped in an atomic transaction so a
      Celery dispatch failure cannot leave an orphaned user without a token.

    Args:
        email:     Normalised (lowercase) email, already validated by the serializer.
        full_name: Stripped display name, already validated by the serializer.

    Raises:
        ValidationError: If a race condition creates a duplicate email between
                         serializer validation and DB insert.
    """
    from apps.accounts.tasks import send_magic_link_email

    with transaction.atomic():
        try:
            user = User.objects.create_user(
                email=email,
                full_name=full_name,
                password=None,          # passwordless by default
                role=User.Role.CLIENT,
                is_active=True,
                is_email_verified=False,
            )
        except IntegrityError:
            # Race condition: another request registered the same email between
            # serializer validation and this insert. Surface a safe error.
            log.warning("Registration race condition for email: %s", email)
            raise ValidationError(
                {"email": "A user with this email already exists."}
            )

        raw_token  = _generate_raw_token()
        token_hash = _sha256(raw_token)
        expires_at = _magic_link_ttl()

        MagicLinkToken.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=expires_at,
        )

    # Dispatch AFTER the transaction commits so the token record is visible to
    # the worker (which runs in a separate process/thread).
    send_magic_link_email.delay(str(user.pk), raw_token)

    log.info(
        "New client registered: user_id=%s email=%s",
        user.pk, email,
    )


def request_magic_link(email: str) -> None:
    """
    Issue a magic-link token for *email* and dispatch the email via Celery.

    Always returns silently — never reveals whether *email* exists in the system
    (anti-enumeration).  The Celery task handles delivery failure asynchronously.

    Args:
        email: Normalised (lowercase) email address from the serializer.
    """
    from apps.accounts.tasks import send_magic_link_email

    try:
        user = User.objects.get(
            email=email,
            is_active=True,
            deleted_at__isnull=True,
            role=User.Role.CLIENT,
        )
    except User.DoesNotExist:
        log.debug("Magic link requested for unknown/inactive email: %s", email)
        return

    if user.is_locked:
        log.warning("Magic link requested for locked account: user_id=%s", user.pk)
        return

    raw_token  = _generate_raw_token()
    token_hash = _sha256(raw_token)
    expires_at = _magic_link_ttl()

    MagicLinkToken.objects.create(
        user=user,
        token_hash=token_hash,
        expires_at=expires_at,
    )

    send_magic_link_email.delay(str(user.pk), raw_token)
    log.info("Magic link issued for user_id=%s", user.pk)


def verify_magic_link(raw_token: str, meta: _RequestMeta) -> dict:
    """
    Validate *raw_token*, authenticate the user, and issue a JWT pair.

    Steps (all inside a DB transaction):
      1. Hash the raw token and look it up.
      2. Assert the token is valid (not used, not expired).
      3. Consume the token atomically (select_for_update prevents double-use).
      4. Update last_login / last_login_ip / reset failed attempts.
      5. Mark email as verified (magic link proves ownership).
      6. Mint a SimpleJWT refresh + access token pair.
      7. Persist the refresh token in UserRefreshToken.

    Args:
        raw_token: The unhashed token from the magic-link URL query string.
        meta:      Dict with `ip_address` and `user_agent` from the request.

    Returns:
        Dict with keys: access (str), refresh (str), user (User instance).

    Raises:
        AuthenticationFailed: Token is missing, invalid, used, or expired.
    """
    token_hash = _sha256(raw_token)

    with transaction.atomic():
        try:
            token_obj = (
                MagicLinkToken.objects
                .select_related("user")
                .select_for_update()      # row-level lock: prevents concurrent double-use
                .get(token_hash=token_hash)
            )
        except MagicLinkToken.DoesNotExist:
            raise AuthenticationFailed("Invalid or expired token.")

        if not token_obj.is_valid:
            raise AuthenticationFailed("Token has already been used or has expired.")

        user = token_obj.user

        if not user.is_active or user.deleted_at is not None:
            raise AuthenticationFailed("This account is no longer active.")

        if user.is_locked:
            raise AuthenticationFailed(
                "Account is temporarily locked. Please try again later."
            )

        token_obj.consume()

        user.last_login        = timezone.now()
        user.last_login_ip     = meta.get("ip_address")
        user.is_email_verified = True
        user.save(update_fields=["last_login", "last_login_ip", "is_email_verified"])
        user.reset_failed_login()   # clears failed_login_attempts + locked_until

        refresh_jwt = RefreshToken.for_user(user)
        access_jwt  = refresh_jwt.access_token

        _store_refresh_token(user=user, refresh_jwt=refresh_jwt, meta=meta)

    log.info(
        "Magic link verified: user_id=%s ip=%s",
        user.pk, meta.get("ip_address"),
    )

    return {
        "access":  str(access_jwt),
        "refresh": str(refresh_jwt),
        "user":    user,
    }


def refresh_access_token(raw_refresh: str, meta: _RequestMeta) -> dict:
    """
    Validate the incoming refresh token, check our revocation record,
    rotate the token pair, and update tracking metadata.

    Revocation escalation: if a token marked `revoked=True` is replayed, we
    assume token theft and immediately revoke ALL sessions for the user.

    Args:
        raw_refresh: The raw JWT refresh token string from the client.
        meta:        Request metadata (ip_address, user_agent).

    Returns:
        Dict with keys: access (str), refresh (str), user (User instance).

    Raises:
        AuthenticationFailed: Token invalid, revoked, expired, or account inactive.
    """
    try:
        old_refresh = RefreshToken(raw_refresh)
    except TokenError as exc:
        raise AuthenticationFailed(str(exc))

    jti = str(old_refresh["jti"])

    with transaction.atomic():
        try:
            stored = (
                UserRefreshToken.objects
                .select_related("user")
                .select_for_update()
                .get(jti=jti)
            )
        except UserRefreshToken.DoesNotExist:
            raise AuthenticationFailed("Refresh token not recognised.")

        if stored.revoked:
            log.warning(
                "Revoked token replay detected — revoking all sessions for user_id=%s",
                stored.user_id,
            )
            UserRefreshToken.objects.filter(user=stored.user).update(revoked=True)
            raise AuthenticationFailed(
                "Token has been revoked. Please log in again."
            )

        if stored.expires_at < timezone.now():
            raise AuthenticationFailed("Refresh token has expired.")

        user = stored.user
        if not user.is_active or user.deleted_at is not None:
            raise AuthenticationFailed("This account is no longer active.")

        stored.revoke()

        new_refresh = RefreshToken.for_user(user)
        new_access  = new_refresh.access_token

        _store_refresh_token(user=user, refresh_jwt=new_refresh, meta=meta)

    log.info("Token rotated for user_id=%s device=%s", user.pk, stored.device_name)

    return {
        "access":  str(new_access),
        "refresh": str(new_refresh),
        "user":    user,
    }


def logout(user, raw_refresh: str, all_devices: bool = False) -> None:
    """
    Revoke one or all refresh tokens for *user*.

    Args:
        user:        The authenticated User instance.
        raw_refresh: JWT refresh token string identifying the current session.
        all_devices: If True, revoke every active session for this user.

    Raises:
        ValidationError: Token does not belong to the authenticated user.
    """
    if all_devices:
        revoked_count = (
            UserRefreshToken.objects
            .filter(user=user, revoked=False)
            .update(revoked=True)
        )
        log.info(
            "All-device logout: user_id=%s sessions_revoked=%d",
            user.pk, revoked_count,
        )
        return

    try:
        refresh_jwt = RefreshToken(raw_refresh)
        jti = str(refresh_jwt["jti"])
    except TokenError:
        log.debug(
            "Logout received an already-invalid token for user_id=%s — treating as success.",
            user.pk,
        )
        return

    try:
        stored = UserRefreshToken.objects.get(jti=jti, user=user)
    except UserRefreshToken.DoesNotExist:
        log.warning(
            "Logout attempt with foreign token for user_id=%s", user.pk
        )
        raise ValidationError("Token does not belong to the authenticated user.")

    stored.revoke()
    log.info(
        "Single-device logout: user_id=%s device=%s",
        user.pk, stored.device_name,
    )


def change_password(user, current_password: str | None, new_password: str) -> None:
    """
    Set or change the user's password.

    For magic-link-only users (no usable password) *current_password* may be
    omitted.  For users who already have a password it is required and verified.

    Args:
        user:             The authenticated User instance.
        current_password: Existing password (required when user.has_usable_password()).
        new_password:     The validated new password (already checked by serializer).

    Raises:
        ValidationError: Current password is missing or incorrect.
    """
    if user.has_usable_password():
        if not current_password:
            raise ValidationError(
                {"current_password": "Current password is required to set a new one."}
            )
        if not user.check_password(current_password):
            user.increment_failed_login()
            raise ValidationError(
                {"current_password": "Current password is incorrect."}
            )

    user.set_password(new_password)
    user.password_last_changed = timezone.now()
    user.save(update_fields=["password", "password_last_changed"])

    log.info("Password changed for user_id=%s", user.pk)


# ──────────────────────────────────────────────────────────────────────────────
# PRIVATE HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _store_refresh_token(
    user,
    refresh_jwt: RefreshToken,
    meta: _RequestMeta,
) -> "UserRefreshToken":
    """
    Persist a new UserRefreshToken record from a freshly minted JWT.

    Args:
        user:        Owner of the token.
        refresh_jwt: The RefreshToken instance from SimpleJWT.
        meta:        Request metadata (ip_address, user_agent).

    Returns:
        The newly created UserRefreshToken instance.
    """
    from datetime import timezone as dt_tz

    jti        = str(refresh_jwt["jti"])
    exp_ts     = refresh_jwt["exp"]
    expires_at = datetime.fromtimestamp(exp_ts, tz=dt_tz.utc)

    user_agent  = meta.get("user_agent", "")
    device_name = _parse_device_name(user_agent)

    return UserRefreshToken.objects.create(
        user=user,
        jti=jti,
        expires_at=expires_at,
        device_name=device_name,
        ip_address=meta.get("ip_address"),
        user_agent=user_agent,
    )