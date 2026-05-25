"""
apps/accounts/services/user_service.py
───────────────────────────────────────
User and profile business logic.
Views call these functions; nothing here knows about HTTP.

Public surface
--------------
  get_me(user)                → User   (with select_related preloaded)
  update_me(user, validated)  → User
"""

from __future__ import annotations

import logging

from django.db import transaction

from apps.accounts.models import User, UserProfile

log = logging.getLogger(__name__)


def get_me(user: User) -> User:
    """
    Return the authenticated user with all related data pre-fetched in a
    single query (tenant + profile), scoped strictly to *user* to prevent
    any possibility of cross-tenant data leakage.

    Args:
        user: The authenticated User instance from request.user.

    Returns:
        A refreshed User instance with tenant and profile selected.
    """
    return (
        User.objects
        .select_related("tenant", "profile")
        .get(pk=user.pk, deleted_at__isnull=True, is_active=True)
    )


def update_me(user: User, validated_data: dict) -> User:
    """
    Apply validated data from UserUpdateSerializer to the user and their profile.

    Only fields explicitly included in *validated_data* are modified — safe for
    partial (PATCH) updates.  email and tenant are never touched here (blocked
    at the serializer level).

    Args:
        user:           The authenticated User instance.
        validated_data: Output of UserUpdateSerializer.validated_data.

    Returns:
        The updated User instance (re-fetched with related data).
    """
    profile_data: dict = validated_data.pop("profile", {})
    user_fields_changed: list[str] = []

    with transaction.atomic():
        # ── User-level fields ─────────────────────────────────────────────────
        if "full_name" in validated_data:
            user.full_name = validated_data["full_name"]
            user_fields_changed.append("full_name")

        if user_fields_changed:
            user.save(update_fields=user_fields_changed)
            log.info(
                "User fields updated: user_id=%s fields=%s",
                user.pk, user_fields_changed,
            )

        # ── Profile-level fields ──────────────────────────────────────────────
        if profile_data:
            profile, created = UserProfile.objects.get_or_create(user=user)
            if created:
                log.warning(
                    "UserProfile was missing for user_id=%s — created on update.",
                    user.pk,
                )

            profile_fields_changed: list[str] = []
            for field, value in profile_data.items():
                setattr(profile, field, value)
                profile_fields_changed.append(field)

            if profile_fields_changed:
                profile.save(update_fields=profile_fields_changed)
                log.info(
                    "Profile fields updated: user_id=%s fields=%s",
                    user.pk, profile_fields_changed,
                )

    return get_me(user)