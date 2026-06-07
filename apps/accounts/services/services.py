"""
apps/accounts/services/services.py
──────────────────────────
AuthService — all authentication business logic.

Keeps views thin; all DB mutations, token generation, and email dispatch
live here.  Every public method is atomic where multiple writes are involved.

Covers
------
- register()              → create user, send verification email
- verify_email()          → mark email verified
- login()                 → issue JWT pair, record session
- magic_link_request()    → create magic-link token, send email
- magic_link_verify()     → consume token, issue JWT pair
- password_reset_request()→ create reset token, send email
- password_reset_confirm()→ consume token, set new password
- google_oauth()          → verify Google ID token, create/fetch user, issue JWT
- refresh_token()         → rotate refresh token (optional), return new access
- logout()                → revoke session
- change_password()       → update password, revoke all other sessions
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework_simplejwt.tokens import RefreshToken

from ..models import (
    EmailVerificationToken,
    MagicLinkToken,
    PasswordResetToken,
    User,
    UserRefreshToken,
)

logger = logging.getLogger("apps.accounts")


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _generate_token(nbytes: int = 32) -> str:
    """Return a cryptographically secure URL-safe token string."""
    return secrets.token_urlsafe(nbytes)


def _issue_jwt_pair(user: User) -> dict:
    """
    Create a SimpleJWT refresh + access token pair for `user`.
    Returns {"access": str, "refresh": str, "access_expires_at": datetime}.
    """
    refresh        = RefreshToken.for_user(user)
    access         = refresh.access_token
    access_minutes = settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds() / 60
    return {
        "access":           str(access),
        "refresh":          str(refresh),
        "access_expires_at": timezone.now() + timedelta(minutes=access_minutes),
    }


def _record_session(
    user: User,
    refresh_token_str: str,
    request,
) -> UserRefreshToken:
    """
    Persist a UserRefreshToken record so the session is trackable.
    """
    refresh = RefreshToken(refresh_token_str)
    jti     = str(refresh.get("jti", ""))

    # Extract device info from the request
    ip          = _get_client_ip(request)
    user_agent  = request.META.get("HTTP_USER_AGENT", "")
    device_name = _device_label(user_agent)

    expires_at = timezone.now() + settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]

    return UserRefreshToken.objects.create(
        user=user,
        jti=jti,
        expires_at=expires_at,
        ip_address=ip,
        user_agent=user_agent,
        device_name=device_name,
    )


def _get_client_ip(request) -> str | None:
    """Extract the real client IP (respects X-Forwarded-For in proxy setups)."""
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _device_label(user_agent: str) -> str:
    """Very naive UA → human label.  Replace with ua-parser for production."""
    ua = user_agent.lower()
    if "mobile" in ua:
        return "Mobile Browser"
    if "chrome" in ua:
        return "Chrome Browser"
    if "firefox" in ua:
        return "Firefox Browser"
    if "safari" in ua:
        return "Safari Browser"
    return "Unknown Device"


def _send_email(subject: str, to: str, html_body: str) -> None:
    """
    Thin wrapper around Django's send_mail.
    Catches and logs exceptions so auth flows are not disrupted by SMTP errors.
    """
    try:
        send_mail(
            subject=subject,
            message="",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[to],
            html_message=html_body,
            fail_silently=False,
        )
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to send email to %s: %s", to, exc)


# ──────────────────────────────────────────────────────────────────────────────
# AUTH SERVICE
# ──────────────────────────────────────────────────────────────────────────────

class AuthService:
    """
    Stateless service class.  All methods are class-methods; instantiate
    where you prefer, or call as AuthService.register(...).
    """

    # ── 1. REGISTER ───────────────────────────────────────────────────────────

    @classmethod
    @transaction.atomic
    def register(cls, validated_data: dict) -> User:
        """
        Create a new CLIENT user and dispatch a verification email.
        Raises ValidationError on password policy failure.
        """
        email    = validated_data["email"]
        password = validated_data["password"]

        # Run Django's built-in password validators
        try:
            validate_password(password)
        except DjangoValidationError as exc:
            raise ValidationError({"password": list(exc.messages)})

        user = User.objects.create_user(
            email=email,
            full_name=validated_data["full_name"],
            password=password,
            role=User.Role.CLIENT,
            terms_accepted_at=timezone.now() if validated_data.get("terms_accepted") else None,
        )

        cls._send_verification_email(user)

        logger.info("New user registered: %s (id=%s)", user.email, user.id)
        return user

    # ── 2. EMAIL VERIFICATION ─────────────────────────────────────────────────

    @classmethod
    def _send_verification_email(cls, user: User) -> None:
        raw_token  = _generate_token()
        token_hash = _sha256(raw_token)
        expires_at = timezone.now() + timedelta(
            hours=settings.EMAIL_VERIFICATION_EXPIRY_HOURS
        )

        # Invalidate previous active verification tokens for this user.
        EmailVerificationToken.objects.filter(user=user, used=False).update(
            used=True, used_at=timezone.now()
        )

        EmailVerificationToken.objects.create(
            user=user,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        verify_url = (
            f"{settings.FRONTEND_BASE_URL}/auth/verify-email?token={raw_token}"
        )
        html = (
            f"<p>Hi {user.full_name},</p>"
            f"<p>Please verify your email: "
            f"<a href='{verify_url}'>Verify Email</a></p>"
            f"<p>This link expires in {settings.EMAIL_VERIFICATION_EXPIRY_HOURS} hours.</p>"
        )
        _send_email("Verify your email address", user.email, html)

    @classmethod
    @transaction.atomic
    def verify_email(cls, ev_token: EmailVerificationToken) -> None:
        ev_token.consume()
        user = ev_token.user
        user.is_email_verified = True
        user.save(update_fields=["is_email_verified"])
        logger.info("Email verified for user %s", user.email)

    # ── 3. PASSWORD LOGIN ─────────────────────────────────────────────────────

    @classmethod
    def login(cls, user: User, request) -> dict:
        """
        Issue a JWT pair, record the session, and update last_login_ip.
        Returns the token payload dict.
        """
        tokens = _issue_jwt_pair(user)
        _record_session(user, tokens["refresh"], request)

        # Reset failed attempts on successful login
        user.reset_failed_login()

        # Update last_login_ip
        user.last_login_ip = _get_client_ip(request)
        user.save(update_fields=["last_login_ip"])

        logger.info(
            "User logged in: %s from %s",
            user.email,
            user.last_login_ip,
        )
        return tokens

    # ── 4. MAGIC LINK ─────────────────────────────────────────────────────────

    @classmethod
    def magic_link_request(cls, email: str) -> None:
        """
        Generate a magic link token and email it.
        Silently returns if no account exists (prevents enumeration).
        """
        try:
            user = User.objects.get(
                email=email, is_active=True, deleted_at__isnull=True
            )
        except User.DoesNotExist:
            logger.debug("Magic link requested for unknown email: %s", email)
            return

        # Invalidate previous active tokens for this user
        MagicLinkToken.objects.filter(user=user, used=False).update(
            used=True, used_at=timezone.now()
        )

        raw_token  = _generate_token()
        token_hash = _sha256(raw_token)
        expires_at = timezone.now() + timedelta(
            minutes=settings.MAGIC_LINK_EXPIRY_MINUTES
        )

        MagicLinkToken.objects.create(
            user=user, token_hash=token_hash, expires_at=expires_at
        )

        link = f"{settings.FRONTEND_BASE_URL}/auth/magic-link?token={raw_token}"
        html = (
            f"<p>Hi {user.full_name},</p>"
            f"<p>Click to log in: <a href='{link}'>Sign In</a></p>"
            f"<p>This link expires in {settings.MAGIC_LINK_EXPIRY_MINUTES} minutes "
            f"and can only be used once.</p>"
        )
        _send_email("Your sign-in link", user.email, html)
        logger.info("Magic link sent to %s", email)

    @classmethod
    @transaction.atomic
    def magic_link_verify(cls, ml_token: MagicLinkToken, request) -> dict:
        ml_token.consume()
        user = ml_token.user

        # Auto-verify email if not yet done (user clicked the link → proves ownership)
        if not user.is_email_verified:
            user.is_email_verified = True
            user.save(update_fields=["is_email_verified"])

        tokens = _issue_jwt_pair(user)
        _record_session(user, tokens["refresh"], request)

        user.last_login_ip = _get_client_ip(request)
        user.save(update_fields=["last_login_ip"])

        logger.info("Magic link login for user %s", user.email)
        return tokens

    # ── 5. PASSWORD RESET ─────────────────────────────────────────────────────

    @classmethod
    def password_reset_request(cls, email: str) -> None:
        """
        Send a password-reset email.
        Silently returns if no account exists.
        """
        try:
            user = User.objects.get(
                email=email, is_active=True, deleted_at__isnull=True
            )
        except User.DoesNotExist:
            logger.debug("Password reset requested for unknown email: %s", email)
            return

        # Invalidate previous active reset tokens
        PasswordResetToken.objects.filter(user=user, used=False).update(
            used=True, used_at=timezone.now()
        )

        raw_token  = _generate_token()
        token_hash = _sha256(raw_token)
        expires_at = timezone.now() + timedelta(
            minutes=settings.PASSWORD_RESET_EXPIRY_MINUTES
        )

        PasswordResetToken.objects.create(
            user=user, token_hash=token_hash, expires_at=expires_at
        )

        link = (
            f"{settings.FRONTEND_BASE_URL}/auth/reset-password?token={raw_token}"
        )
        html = (
            f"<p>Hi {user.full_name},</p>"
            f"<p>Reset your password: <a href='{link}'>Reset Password</a></p>"
            f"<p>This link expires in {settings.PASSWORD_RESET_EXPIRY_MINUTES} minutes.</p>"
            f"<p>If you did not request this, please ignore it.</p>"
        )
        _send_email("Reset your password", user.email, html)
        logger.info("Password reset email sent to %s", email)

    @classmethod
    @transaction.atomic
    def password_reset_confirm(
        cls,
        reset_token: PasswordResetToken,
        new_password: str,
    ) -> None:
        try:
            validate_password(new_password)
        except DjangoValidationError as exc:
            raise ValidationError({"new_password": list(exc.messages)})

        reset_token.consume()
        user = reset_token.user
        user.set_password(new_password)
        user.password_last_changed = timezone.now()
        user.failed_login_attempts = 0
        user.locked_until          = None
        user.save(update_fields=[
            "password", "password_last_changed",
            "failed_login_attempts", "locked_until",
        ])

        # Revoke all existing sessions for security
        UserRefreshToken.objects.filter(user=user, revoked=False).update(revoked=True)
        logger.info("Password reset confirmed for user %s", user.email)

    # ── 6. GOOGLE OAUTH2 ─────────────────────────────────────────────────────

    @classmethod
    @transaction.atomic
    def google_oauth(cls, credential: str, request) -> dict:
        """
        Verify the Google ID token, create or fetch the User, and issue a
        JWT pair.

        Steps
        -----
        1. Verify the Google credential with google-auth.
        2. Extract sub, email, name, picture from the ID token claims.
        3. Look up by google_sub first (handles email changes).
        4. If not found by sub, try email (link existing account).
        5. If still not found, create a new CLIENT account.
        6. Issue access + refresh tokens.
        """
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token
        from google.auth.exceptions import GoogleAuthError

        client_id = settings.GOOGLE_OAUTH2_CLIENT_ID

        try:
            id_info = google_id_token.verify_oauth2_token(
                credential,
                google_requests.Request(),
                client_id,
            )
        except (GoogleAuthError, ValueError) as exc:
            logger.warning("Google token verification failed: %s", exc)
            raise AuthenticationFailed("Invalid Google credential.")

        google_sub = id_info.get("sub")
        email      = id_info.get("email", "").lower().strip()
        full_name  = id_info.get("name", "")
        picture    = id_info.get("picture", "")

        if not google_sub or not email:
            raise AuthenticationFailed(
                "Google token is missing required claims (sub, email)."
            )

        if not id_info.get("email_verified"):
            raise AuthenticationFailed(
                "Google account email is not verified."
            )

        # 3. Try to find by google_sub
        user = User.objects.filter(
            google_sub=google_sub, deleted_at__isnull=True
        ).first()

        if user is None:
            # 4. Try to link existing account by email
            user = User.objects.filter(
                email=email, deleted_at__isnull=True
            ).first()

            if user is not None:
                # Link the existing account to Google
                user.google_sub         = google_sub
                user.google_picture_url = picture
                user.is_email_verified  = True
                user.save(update_fields=[
                    "google_sub", "google_picture_url", "is_email_verified"
                ])
                logger.info("Linked Google account to existing user: %s", email)
            else:
                # 5. Create a brand-new account
                user = User.objects.create_user(
                    email=email,
                    full_name=full_name or email,
                    password=None,          # no local password for OAuth users
                    role=User.Role.CLIENT,
                    google_sub=google_sub,
                    google_picture_url=picture,
                    is_email_verified=True,
                    terms_accepted_at=timezone.now(),
                )
                # Set unusable password explicitly
                user.set_unusable_password()
                user.save(update_fields=["password"])
                logger.info("Created new user via Google OAuth: %s", email)
        else:
            # Refresh picture on every login
            if user.google_picture_url != picture:
                user.google_picture_url = picture
                user.save(update_fields=["google_picture_url"])

        if not user.is_active:
            raise AuthenticationFailed("This account has been deactivated.")

        # 6. Issue tokens
        tokens = _issue_jwt_pair(user)
        _record_session(user, tokens["refresh"], request)

        user.last_login_ip = _get_client_ip(request)
        user.save(update_fields=["last_login_ip"])

        logger.info("Google OAuth login for user %s", user.email)
        return tokens

    # ── 7. TOKEN REFRESH ──────────────────────────────────────────────────────

    @classmethod
    @transaction.atomic
    def refresh_token(cls, refresh_token_str: str, request) -> dict:
        """
        Validate and rotate a refresh token.
        The old session record is revoked; a new one is created.
        """
        from rest_framework_simplejwt.exceptions import TokenError

        try:
            old_refresh = RefreshToken(refresh_token_str)
        except TokenError as exc:
            raise AuthenticationFailed(f"Invalid refresh token: {exc}")

        old_jti = str(old_refresh.get("jti", ""))

        try:
            session = UserRefreshToken.objects.get(jti=old_jti)
        except UserRefreshToken.DoesNotExist:
            raise AuthenticationFailed(
                "Session not found. Please log in again."
            )

        if session.revoked:
            # Possible token reuse attack — revoke ALL sessions for this user
            UserRefreshToken.objects.filter(
                user=session.user, revoked=False
            ).update(revoked=True)
            logger.warning(
                "Revoked refresh token reuse detected for user %s",
                session.user.email,
            )
            raise AuthenticationFailed(
                "Security alert: token reuse detected. All sessions revoked."
            )

        if session.expires_at < timezone.now():
            raise AuthenticationFailed("Refresh token has expired. Please log in again.")

        user = session.user
        if not user.is_active or user.deleted_at:
            raise AuthenticationFailed("Account is no longer active.")

        # Revoke old session and issue new tokens
        session.revoke()

        new_tokens = _issue_jwt_pair(user)
        _record_session(user, new_tokens["refresh"], request)

        return new_tokens

    # ── 8. LOGOUT ─────────────────────────────────────────────────────────────

    @classmethod
    def logout(cls, refresh_token_str: str, user: User) -> None:
        """Revoke the session associated with the given refresh token."""
        from rest_framework_simplejwt.exceptions import TokenError

        try:
            refresh = RefreshToken(refresh_token_str)
        except TokenError as exc:
            raise AuthenticationFailed(f"Invalid refresh token: {exc}")

        jti = str(refresh.get("jti", ""))
        updated = UserRefreshToken.objects.filter(user=user, jti=jti).update(revoked=True)
        if not updated:
            raise AuthenticationFailed("Session not found for this user.")

        logger.info("User logged out: %s", user.email)

    # ── 9. CHANGE PASSWORD ────────────────────────────────────────────────────

    @classmethod
    @transaction.atomic
    def change_password(
        cls,
        user: User,
        new_password: str,
        current_refresh: str | None = None,
    ) -> None:
        """
        Set new password and revoke all sessions except the current one
        (so the user stays logged in on the active device).
        """
        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as exc:
            raise ValidationError({"new_password": list(exc.messages)})

        user.set_password(new_password)
        user.password_last_changed = timezone.now()
        user.save(update_fields=["password", "password_last_changed"])

        # Revoke all sessions except the current one
        qs = UserRefreshToken.objects.filter(user=user, revoked=False)
        if current_refresh:
            from rest_framework_simplejwt.exceptions import TokenError
            try:
                refresh = RefreshToken(current_refresh)
                jti     = str(refresh.get("jti", ""))
                qs = qs.exclude(jti=jti)
            except TokenError as exc:
                raise AuthenticationFailed(f"Invalid current refresh token: {exc}")
        qs.update(revoked=True)

        logger.info("Password changed for user %s", user.email)