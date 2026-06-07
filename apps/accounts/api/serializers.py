"""
apps/accounts/api/serializers.py
─────────────────────────────
DRF serializers for every authentication and profile endpoint.

Covers
------
- Registration (email + password)
- Email / password login
- Email verification
- Magic link (request + verify)
- Password reset (request + confirm)
- Google OAuth2 (ID-token exchange)
- Token refresh + logout
- User profile (read + partial update)
- Change password
- Active sessions (refresh tokens)
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework import serializers

from ..models import (
    EmailVerificationToken,
    MagicLinkToken,
    PasswordResetToken,
    User,
    UserProfile,
    UserRefreshToken,
)


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _sha256(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# 1. REGISTRATION
# ──────────────────────────────────────────────────────────────────────────────

class UserRegistrationSerializer(serializers.Serializer):
    """
    Validates new-user registration data.
    Passwords are never stored in the serializer; hashing happens in AuthService.
    """

    email     = serializers.EmailField(max_length=255)
    full_name = serializers.CharField(max_length=255)
    password  = serializers.CharField(
        write_only=True, min_length=8,
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )
    # Optional: accept terms at registration time
    terms_accepted = serializers.BooleanField(default=False)

    def validate_email(self, value: str) -> str:
        value = value.lower().strip()
        if User.objects.filter(
            email__iexact=value, deleted_at__isnull=True
        ).exists():
            raise serializers.ValidationError(
                "An account with this email already exists."
            )
        return value

    def validate(self, data: dict) -> dict:
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Passwords do not match."}
            )
        if not data.get("terms_accepted"):
            raise serializers.ValidationError(
                {"terms_accepted": "You must accept the terms and conditions."}
            )
        return data


# ──────────────────────────────────────────────────────────────────────────────
# 2. EMAIL / PASSWORD LOGIN
# ──────────────────────────────────────────────────────────────────────────────

class EmailLoginSerializer(serializers.Serializer):
    """
    Standard credential login.
    Returns the validated user object via .validated_data["user"].
    """

    email    = serializers.EmailField(max_length=255)
    password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    def validate(self, data: dict) -> dict:
        email    = data["email"].lower().strip()
        password = data["password"]

        invalid_credentials = "Invalid email or password."

        try:
            user = User.objects.get(email=email, deleted_at__isnull=True)
        except User.DoesNotExist:
            raise serializers.ValidationError(invalid_credentials)

        if not user.is_active:
            raise serializers.ValidationError("This account has been deactivated.")

        if user.is_locked:
            raise serializers.ValidationError(
                f"Account locked until {user.locked_until.strftime('%Y-%m-%d %H:%M UTC')}. "
                "Use magic link or password reset to regain access."
            )

        if not user.check_password(password):
            user.increment_failed_login()
            # Lock after MAX_FAILED_LOGIN_ATTEMPTS (default 5)
            max_attempts = getattr(settings, "MAX_FAILED_LOGIN_ATTEMPTS", 5)
            lock_minutes = getattr(settings, "ACCOUNT_LOCK_MINUTES", 30)
            if user.failed_login_attempts >= max_attempts:
                user.lock_account(
                    until=timezone.now() + timedelta(minutes=lock_minutes)
                )
            raise serializers.ValidationError(invalid_credentials)

        if not user.is_email_verified:
            raise serializers.ValidationError(
                "Please verify your email address before logging in."
            )

        data["user"] = user
        return data


# ──────────────────────────────────────────────────────────────────────────────
# 3. EMAIL VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────

class EmailVerifySerializer(serializers.Serializer):
    """Accepts the raw token from the verification link."""

    token = serializers.CharField(max_length=128)

    def validate_token(self, value: str) -> str:
        token_hash = _sha256(value)
        try:
            ev_token = EmailVerificationToken.objects.select_related("user").get(
                token_hash=token_hash
            )
        except EmailVerificationToken.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired verification token.")

        if not ev_token.is_valid:
            raise serializers.ValidationError("This verification link has expired.")

        self.context["ev_token"] = ev_token
        return value


# ──────────────────────────────────────────────────────────────────────────────
# 4. MAGIC LINK
# ──────────────────────────────────────────────────────────────────────────────

class MagicLinkRequestSerializer(serializers.Serializer):
    """
    Request a passwordless login link.
    Always returns 200 (prevents email enumeration).
    """

    email = serializers.EmailField(max_length=255)

    def validate_email(self, value: str) -> str:
        return value.lower().strip()


class MagicLinkVerifySerializer(serializers.Serializer):
    """Accepts the raw token from the magic link URL."""

    token = serializers.CharField(max_length=128)

    def validate_token(self, value: str) -> str:
        token_hash = _sha256(value)
        try:
            ml_token = MagicLinkToken.objects.select_related("user").get(
                token_hash=token_hash
            )
        except MagicLinkToken.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired magic link.")

        if not ml_token.is_valid:
            raise serializers.ValidationError("This magic link has expired.")

        user = ml_token.user
        if not user.is_active or user.deleted_at:
            raise serializers.ValidationError("This account is no longer active.")

        self.context["ml_token"] = ml_token
        return value


# ──────────────────────────────────────────────────────────────────────────────
# 5. PASSWORD RESET
# ──────────────────────────────────────────────────────────────────────────────

class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Triggers a password-reset email.
    Always returns 200 (prevents email enumeration).
    """

    email = serializers.EmailField(max_length=255)

    def validate_email(self, value: str) -> str:
        return value.lower().strip()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Validates the raw reset token and new password."""

    token            = serializers.CharField(max_length=128)
    password         = serializers.CharField(
        write_only=True, min_length=8,
        style={"input_type": "password"},
    )
    password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )

    def validate(self, data: dict) -> dict:
        if data["password"] != data["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Passwords do not match."}
            )

        token_hash = _sha256(data["token"])
        try:
            reset_token = PasswordResetToken.objects.select_related("user").get(
                token_hash=token_hash
            )
        except PasswordResetToken.DoesNotExist:
            raise serializers.ValidationError({"token": "Invalid or expired token."})

        if not reset_token.is_valid:
            raise serializers.ValidationError({"token": "This reset link has expired."})

        self.context["reset_token"] = reset_token
        return data


# ──────────────────────────────────────────────────────────────────────────────
# 6. GOOGLE OAUTH2
# ──────────────────────────────────────────────────────────────────────────────

class GoogleOAuthSerializer(serializers.Serializer):
    """
    Accepts the Google ID token (credential) sent by the Next.js frontend
    after the user completes the Google sign-in flow.

    Flow
    ----
    1. Frontend: user clicks "Sign in with Google" (using @react-oauth/google).
    2. Google returns a credential (signed JWT / ID token).
    3. Frontend POSTs { "credential": "<id_token>" } to /api/auth/google/.
    4. Backend verifies the token with Google's public keys.
    5. Backend creates or fetches the User, returns access + refresh tokens.

    The actual verification and user creation happen in AuthService.google_oauth().
    This serializer only checks that the field is present and non-empty.
    """

    credential = serializers.CharField(
        help_text="Google ID token returned by @react-oauth/google."
    )


# ──────────────────────────────────────────────────────────────────────────────
# 7. TOKEN REFRESH + LOGOUT
# ──────────────────────────────────────────────────────────────────────────────

class TokenRefreshSerializer(serializers.Serializer):
    """Wraps SimpleJWT token refresh with device tracking."""

    refresh = serializers.CharField()


class LogoutSerializer(serializers.Serializer):
    """
    Accepts the refresh token so the session record can be revoked.
    The access token is short-lived (~15 min) so we don't need to blacklist it.
    """

    refresh = serializers.CharField()


# ──────────────────────────────────────────────────────────────────────────────
# 8. USER PROFILE
# ──────────────────────────────────────────────────────────────────────────────

class UserProfileSerializer(serializers.ModelSerializer):
    """Full read/update serializer for UserProfile."""

    class Meta:
        model  = UserProfile
        fields = [
            "date_of_birth",
            "phone_number",
            "alternate_email",
            "address_line1",
            "address_line2",
            "city",
            "state_province",
            "postal_code",
            "country",
            "profile_picture",
            "bio",
            "preferences",
            "timezone",
            "language",
            "updated_at",
        ]
        read_only_fields = ["updated_at"]


class UserMeSerializer(serializers.ModelSerializer):
    """
    Read-only representation of the authenticated user + nested profile.
    Returned from GET /api/auth/me/.
    """

    profile = UserProfileSerializer(read_only=True)
    role    = serializers.CharField(source="get_role_display")

    class Meta:
        model  = User
        fields = [
            "id",
            "email",
            "full_name",
            "role",
            "is_email_verified",
            "is_oauth_user",
            "google_picture_url",
            "tenant",
            "terms_accepted_at",
            "created_at",
            "profile",
        ]
        read_only_fields = fields


class UserUpdateSerializer(serializers.ModelSerializer):
    """Partial update for the User row (name, legal consent)."""

    profile = UserProfileSerializer(required=False)

    class Meta:
        model  = User
        fields = [
            "full_name",
            "terms_accepted_at",
            "privacy_accepted_version",
            "profile",
        ]

    def update(self, instance: User, validated_data: dict) -> User:
        profile_data = validated_data.pop("profile", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if profile_data:
            profile = instance.profile
            for attr, value in profile_data.items():
                setattr(profile, attr, value)
            profile.save()

        return instance


# ──────────────────────────────────────────────────────────────────────────────
# 9. CHANGE PASSWORD
# ──────────────────────────────────────────────────────────────────────────────

class ChangePasswordSerializer(serializers.Serializer):
    """
    Allows authenticated users to change their own password.
    OAuth-only users (no local password) should use the reset flow instead.
    """

    current_password = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )
    new_password = serializers.CharField(
        write_only=True, min_length=8,
        style={"input_type": "password"},
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        style={"input_type": "password"},
    )
    current_refresh = serializers.CharField(
        write_only=True, required=False, allow_blank=True
    )

    def validate(self, data: dict) -> dict:
        user: User = self.context["request"].user

        if user.is_oauth_user:
            raise serializers.ValidationError(
                "OAuth accounts do not have a local password. "
                "Use the password reset flow to set one."
            )

        if not user.check_password(data["current_password"]):
            raise serializers.ValidationError(
                {"current_password": "Current password is incorrect."}
            )

        if data["new_password"] != data["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password_confirm": "New passwords do not match."}
            )

        if data["current_password"] == data["new_password"]:
            raise serializers.ValidationError(
                {"new_password": "New password must differ from the current one."}
            )

        return data


# ──────────────────────────────────────────────────────────────────────────────
# 10. ACTIVE SESSIONS (Refresh Tokens)
# ──────────────────────────────────────────────────────────────────────────────

class UserRefreshTokenSerializer(serializers.ModelSerializer):
    """Read-only representation of an active session."""

    class Meta:
        model  = UserRefreshToken
        fields = [
            "id",
            "device_name",
            "ip_address",
            "last_used_at",
            "created_at",
            "expires_at",
        ]
        read_only_fields = fields


class RevokeSessionSerializer(serializers.Serializer):
    """Accepts a refresh token ID to revoke a specific session."""

    session_id = serializers.UUIDField(
        help_text="UUID of the UserRefreshToken record to revoke."
    )