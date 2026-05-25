"""
apps/accounts/api/serializers.py
─────────────────────────────────
Input validation and output formatting only — zero business logic.
All models are imported from apps.accounts.models.
"""

from __future__ import annotations

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from apps.accounts.models import User, UserProfile, Tenant


# ──────────────────────────────────────────────────────────────────────────────
# TENANT (nested, read-only)
# ──────────────────────────────────────────────────────────────────────────────

class TenantSerializer(serializers.ModelSerializer):
    """Minimal tenant representation embedded in user responses."""

    class Meta:
        model  = Tenant
        fields = ["slug", "name", "subscription_tier"]
        read_only_fields = fields


# ──────────────────────────────────────────────────────────────────────────────
# USER PROFILE — read + update
# ──────────────────────────────────────────────────────────────────────────────

class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializes UserProfile fields for both reading and partial updates.
    profile_picture is read-only here; a dedicated upload endpoint is recommended.
    """

    profile_picture = serializers.ImageField(read_only=True)

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
        read_only_fields = ["updated_at", "profile_picture"]


# ──────────────────────────────────────────────────────────────────────────────
# USER — read (GET /users/me/)
# ──────────────────────────────────────────────────────────────────────────────

class UserMeSerializer(serializers.ModelSerializer):
    """
    Full user representation returned after login or on GET /users/me/.
    Embeds tenant and profile as nested objects.
    """

    tenant  = TenantSerializer(read_only=True)
    profile = UserProfileSerializer(read_only=True)

    class Meta:
        model  = User
        fields = [
            "id",
            "email",
            "full_name",
            "role",
            "is_email_verified",
            "tenant",
            "profile",
        ]
        read_only_fields = fields


# ──────────────────────────────────────────────────────────────────────────────
# USER — update (PATCH /users/me/)
# ──────────────────────────────────────────────────────────────────────────────

class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Allows updating full_name on the User model.
    Profile fields are handled via the nested profile serializer
    and merged in the view/service layer.
    """

    profile = UserProfileSerializer(required=False)

    class Meta:
        model  = User
        fields = ["full_name", "profile"]

    def validate(self, attrs: dict) -> dict:
        """Block attempts to change protected fields via this endpoint."""
        for forbidden in ("email", "tenant", "role", "is_superuser", "is_staff"):
            if forbidden in self.initial_data:
                raise serializers.ValidationError(
                    {forbidden: f"Updating '{forbidden}' is not allowed through this endpoint."}
                )
        return attrs


# ──────────────────────────────────────────────────────────────────────────────
# REGISTRATION
# ──────────────────────────────────────────────────────────────────────────────

class ClientRegistrationSerializer(serializers.Serializer):
    """
    Input serializer for POST /api/v1/auth/register/.

    Validates that:
      - email is a valid email address (normalised to lowercase).
      - full_name is present and non-empty.
      - email is not already in use by a non-deleted user.

    Does NOT create the user — that responsibility belongs to auth_service.register_client().
    """

    email     = serializers.EmailField(
        max_length=255,
        help_text="Must be unique. Used as the primary login credential.",
    )
    full_name = serializers.CharField(
        max_length=255,
        min_length=2,
        help_text="The user's display name.",
    )

    def validate_email(self, value: str) -> str:
        """Normalise and check uniqueness among active (non-deleted) users."""
        normalised = value.lower().strip()

        if User.objects.filter(email=normalised, deleted_at__isnull=True).exists():
            raise serializers.ValidationError("A user with this email already exists.")

        return normalised

    def validate_full_name(self, value: str) -> str:
        """Strip surrounding whitespace."""
        return value.strip()


# ──────────────────────────────────────────────────────────────────────────────
# AUTH — inputs
# ──────────────────────────────────────────────────────────────────────────────

class MagicLinkRequestSerializer(serializers.Serializer):
    """Input for POST /auth/magic/request/"""

    email = serializers.EmailField(
        help_text="The email address to send the magic link to.",
    )

    def validate_email(self, value: str) -> str:
        return value.lower().strip()


class RefreshTokenSerializer(serializers.Serializer):
    """Input for POST /auth/token/refresh/"""

    refresh = serializers.CharField(
        help_text="A valid, non-revoked SimpleJWT refresh token.",
    )


class LogoutSerializer(serializers.Serializer):
    """Input for POST /auth/logout/"""

    refresh     = serializers.CharField(
        help_text="The refresh token of the session to revoke.",
    )
    all_devices = serializers.BooleanField(
        default=False, required=False,
        help_text="Set true to revoke ALL sessions for this user.",
    )


class ChangePasswordSerializer(serializers.Serializer):
    """
    Input for POST /auth/change-password/.

    current_password is optional for magic-link-only users who are setting a
    password for the first time (they have no usable password yet).
    """

    current_password = serializers.CharField(
        required=False,
        allow_blank=True,
        write_only=True,
        help_text="Required only if the user already has a password set.",
    )
    new_password     = serializers.CharField(
        min_length=8,
        write_only=True,
        help_text="Must pass Django's AUTH_PASSWORD_VALIDATORS.",
    )
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs: dict) -> dict:
        """Cross-field validation: passwords must match and pass Django validators."""
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )
        try:
            validate_password(attrs["new_password"])
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"new_password": list(exc.messages)})
        return attrs


# ──────────────────────────────────────────────────────────────────────────────
# AUTH — outputs
# ──────────────────────────────────────────────────────────────────────────────

class TokenPairSerializer(serializers.Serializer):
    """
    Returned by magic-link verify and token refresh.
    Not a ModelSerializer — values are injected by the service layer.
    """

    access  = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    user    = UserMeSerializer(read_only=True)