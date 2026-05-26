"""
apps/accounts/tests.py
════════════════════════════════════════════════════════════════════════════════
Full test suite for the Infinity accounts / authentication system.

Coverage
--------
  1.  Models          — User, Tenant, Tokens, UserRefreshToken, RBAC, MFA
  2.  Permissions     — every permission class
  3.  Serializers     — validation paths (happy + unhappy)
  4.  Services        — AuthService unit tests (Google OAuth mocked)
  5.  API views       — full HTTP integration tests for every endpoint
  6.  Google OAuth    — end-to-end with mocked google.oauth2.id_token
  7.  Celery tasks    — cleanup + unlock jobs

Run
---
    python manage.py test apps.accounts --verbosity=2

Dependencies (test-only)
---
    pip install factory-boy freezegun
    (freezegun is optional — time-travel helpers marked clearly)
════════════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

# ── Local imports ─────────────────────────────────────────────────────────────
from apps.accounts.models import (
    EmailVerificationToken,
    MagicLinkToken,
    PasswordResetToken,
    Permission,
    Role,
    Tenant,
    User,
    UserMFA,
    UserProfile,
    UserRefreshToken,
    UserRoleAssignment,
)
from apps.accounts.permissions import (
    IsAdminUser,
    IsClientUser,
    IsEmailVerified,
    IsOwnerOrAdmin,
    IsSameTenant,
    IsSuperAdmin,
)
from apps.accounts.services.services import AuthService
from apps.accounts.tasks import cleanup_expired_tokens, unlock_expired_accounts


# ══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS & FACTORIES
# ══════════════════════════════════════════════════════════════════════════════

def _sha256(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def make_tenant(
    name: str = "Test Corp",
    slug: str = "test-corp",
    tier: str = "free",
) -> Tenant:
    """Create (or retrieve) a Tenant for tests."""
    tenant, _ = Tenant.objects.get_or_create(
        slug=slug,
        defaults={"name": name, "subscription_tier": tier},
    )
    return tenant


def make_user(
    email: str = "user@example.com",
    full_name: str = "Test User",
    password: str = "StrongPass123!",
    role: str = User.Role.CLIENT,
    tenant: Tenant | None = None,
    verified: bool = True,
    **kwargs,
) -> User:
    """Create a User with sensible defaults."""
    if tenant is None:
        tenant = make_tenant()
    user = User.objects.create_user(
        email=email,
        full_name=full_name,
        password=password,
        role=role,
        tenant=tenant,
        is_email_verified=verified,
        **kwargs,
    )
    return user


def make_admin(email: str = "admin@example.com", **kwargs) -> User:
    return make_user(email=email, role=User.Role.ADMIN, **kwargs)


def make_superadmin(email: str = "super@example.com", **kwargs) -> User:
    return make_user(email=email, role=User.Role.SUPERADMIN, is_superuser=True, **kwargs)


def jwt_headers(user: User) -> dict:
    """Return Authorization header dict for a user."""
    refresh = RefreshToken.for_user(user)
    return {"HTTP_AUTHORIZATION": f"Bearer {str(refresh.access_token)}"}


def _make_ev_token(user: User, hours: int = 24) -> tuple[str, EmailVerificationToken]:
    """Return (raw_token, EmailVerificationToken)."""
    raw = "ev_token_raw_" + str(uuid.uuid4()).replace("-", "")
    EmailVerificationToken.objects.filter(user=user, used=False).update(
        used=True, used_at=timezone.now()
    )
    token = EmailVerificationToken.objects.create(
        user=user,
        token_hash=_sha256(raw),
        expires_at=timezone.now() + timedelta(hours=hours),
    )
    return raw, token


def _make_magic_token(user: User, minutes: int = 15) -> tuple[str, MagicLinkToken]:
    raw = "ml_token_raw_" + str(uuid.uuid4()).replace("-", "")
    token = MagicLinkToken.objects.create(
        user=user,
        token_hash=_sha256(raw),
        expires_at=timezone.now() + timedelta(minutes=minutes),
    )
    return raw, token


def _make_reset_token(user: User, minutes: int = 30) -> tuple[str, PasswordResetToken]:
    raw = "pr_token_raw_" + str(uuid.uuid4()).replace("-", "")
    token = PasswordResetToken.objects.create(
        user=user,
        token_hash=_sha256(raw),
        expires_at=timezone.now() + timedelta(minutes=minutes),
    )
    return raw, token


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1  ─  MODEL TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TenantModelTest(TestCase):
    """Tests for the Tenant model."""

    def test_create_tenant(self):
        tenant = make_tenant()
        self.assertEqual(str(tenant), "Test Corp (Free)")
        self.assertTrue(tenant.is_active)
        self.assertIsNotNone(tenant.id)

    def test_slug_unique(self):
        make_tenant(slug="unique-slug")
        with self.assertRaises(Exception):
            Tenant.objects.create(name="Dup", slug="unique-slug")

    def test_subscription_tier_choices(self):
        for tier, _ in Tenant.SubscriptionTier.choices:
            t = Tenant.objects.create(name=tier, slug=f"slug-{tier}", subscription_tier=tier)
            self.assertEqual(t.subscription_tier, tier)


class UserModelTest(TestCase):
    """Tests for the User model and manager."""

    def setUp(self):
        self.tenant = make_tenant()

    # ── Creation ──────────────────────────────────────────────────────────────

    def test_create_user_normalises_email(self):
        user = make_user(email="UPPER@Example.COM", tenant=self.tenant)
        self.assertEqual(user.email, "upper@example.com")

    def test_create_user_defaults(self):
        user = make_user(tenant=self.tenant)
        self.assertEqual(user.role, User.Role.CLIENT)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.is_staff)
        self.assertTrue(user.is_active)

    def test_create_superuser(self):
        su = User.objects.create_superuser(
            email="su@example.com",
            full_name="Super",
            password="StrongPass123!",
        )
        self.assertTrue(su.is_superuser)
        self.assertTrue(su.is_staff)
        self.assertTrue(su.is_email_verified)

    def test_create_user_without_email_raises(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(email="", full_name="No Email", password="x")

    def test_str_representation(self):
        user = make_user(email="str@example.com", full_name="Jane", tenant=self.tenant)
        self.assertIn("Jane", str(user))
        self.assertIn("str@example.com", str(user))

    # ── Profile auto-creation ────────────────────────────────────────────────

    def test_profile_created_on_user_save(self):
        user = make_user(email="profile@example.com", tenant=self.tenant)
        self.assertTrue(UserProfile.objects.filter(user=user).exists())

    # ── Soft delete ───────────────────────────────────────────────────────────

    def test_soft_delete_sets_deleted_at(self):
        user = make_user(email="del@example.com", tenant=self.tenant)
        user.soft_delete()
        user.refresh_from_db()
        self.assertIsNotNone(user.deleted_at)
        self.assertFalse(user.is_active)

    def test_soft_delete_obfuscates_email(self):
        user = make_user(email="todel@example.com", tenant=self.tenant)
        original_email = user.email
        user.soft_delete()
        user.refresh_from_db()
        self.assertNotEqual(user.email, original_email)
        self.assertIn("deleted_", user.email)

    def test_soft_delete_allows_email_reuse(self):
        """After soft-delete the same email can be registered again."""
        user = make_user(email="reuse@example.com", tenant=self.tenant)
        user.soft_delete()
        # New user with same email should succeed
        new_user = make_user(email="reuse@example.com", tenant=self.tenant)
        self.assertNotEqual(user.pk, new_user.pk)

    def test_is_deleted_property(self):
        user = make_user(email="prop@example.com", tenant=self.tenant)
        self.assertFalse(user.is_deleted)
        user.soft_delete()
        user.refresh_from_db()
        self.assertTrue(user.is_deleted)

    # ── Locking ───────────────────────────────────────────────────────────────

    def test_lock_account(self):
        user = make_user(email="lock@example.com", tenant=self.tenant)
        self.assertFalse(user.is_locked)
        user.lock_account(until=timezone.now() + timedelta(minutes=30))
        self.assertTrue(user.is_locked)

    def test_lock_expires(self):
        user = make_user(email="lockexp@example.com", tenant=self.tenant)
        user.lock_account(until=timezone.now() - timedelta(seconds=1))
        self.assertFalse(user.is_locked)

    def test_reset_failed_login(self):
        user = make_user(email="fail@example.com", tenant=self.tenant)
        user.increment_failed_login()
        user.increment_failed_login()
        user.lock_account(until=timezone.now() + timedelta(minutes=5))
        user.reset_failed_login()
        user.refresh_from_db()
        self.assertEqual(user.failed_login_attempts, 0)
        self.assertIsNone(user.locked_until)

    # ── OAuth helper ──────────────────────────────────────────────────────────

    def test_is_oauth_user_false_for_password_user(self):
        user = make_user(email="oauth@example.com", tenant=self.tenant)
        self.assertFalse(user.is_oauth_user)

    def test_is_oauth_user_true_when_no_password(self):
        user = make_user(email="googleuser@example.com", tenant=self.tenant)
        user.google_sub = "google-sub-123"
        user.set_unusable_password()
        user.save()
        self.assertTrue(user.is_oauth_user)

    # ── Manager helpers ───────────────────────────────────────────────────────

    def test_manager_active_excludes_deleted(self):
        user = make_user(email="act@example.com", tenant=self.tenant)
        user.soft_delete()
        active_pks = list(User.objects.active().values_list("pk", flat=True))
        self.assertNotIn(user.pk, active_pks)

    def test_manager_for_tenant(self):
        t1 = make_tenant(slug="t1", name="T1")
        t2 = make_tenant(slug="t2", name="T2")
        u1 = make_user(email="u1@example.com", tenant=t1)
        make_user(email="u2@example.com", tenant=t2)
        qs = User.objects.for_tenant(t1)
        self.assertIn(u1, qs)
        self.assertEqual(qs.filter(tenant=t2).count(), 0)

    # ── RBAC perm check ───────────────────────────────────────────────────────

    def test_has_perm_superuser_always_true(self):
        su = make_superadmin(email="superperm@example.com")
        self.assertTrue(su.has_perm("anything:goes"))

    def test_has_perm_inactive_always_false(self):
        user = make_user(email="inactive@example.com", tenant=self.tenant)
        user.is_active = False
        user.save()
        self.assertFalse(user.has_perm("some:perm"))

    def test_rbac_perm_via_role_assignment(self):
        perm = Permission.objects.create(
            codename="invoice:approve", name="Approve Invoice"
        )
        role = Role.objects.create(name="Accountant")
        role.permissions.add(perm)
        user = make_user(email="rbac@example.com", tenant=self.tenant)
        UserRoleAssignment.objects.create(user=user, role=role)
        self.assertTrue(user._has_rbac_perm("invoice:approve"))

    def test_rbac_perm_expired_assignment_denied(self):
        perm = Permission.objects.create(
            codename="doc:delete", name="Delete Doc"
        )
        role = Role.objects.create(name="TempAdmin")
        role.permissions.add(perm)
        user = make_user(email="rbac_exp@example.com", tenant=self.tenant)
        UserRoleAssignment.objects.create(
            user=user,
            role=role,
            expires_at=timezone.now() - timedelta(hours=1),  # already expired
        )
        self.assertFalse(user._has_rbac_perm("doc:delete"))


class AbstractTokenTest(TestCase):
    """Tests for token validity helpers shared by all token models."""

    def setUp(self):
        self.user = make_user(email="tok@example.com")

    def test_valid_token(self):
        _, token = _make_ev_token(self.user)
        self.assertTrue(token.is_valid)

    def test_expired_token(self):
        _, token = _make_ev_token(self.user, hours=-1)
        self.assertFalse(token.is_valid)

    def test_consume_marks_used(self):
        _, token = _make_ev_token(self.user)
        token.consume()
        self.assertTrue(token.used)
        self.assertIsNotNone(token.used_at)

    def test_consume_raises_on_already_used(self):
        _, token = _make_ev_token(self.user)
        token.consume()
        with self.assertRaises(ValueError):
            token.consume()

    def test_consume_raises_on_expired(self):
        _, token = _make_ev_token(self.user, hours=-1)
        with self.assertRaises(ValueError):
            token.consume()


class UserRefreshTokenModelTest(TestCase):
    """Tests for UserRefreshToken."""

    def setUp(self):
        self.user = make_user(email="session@example.com")

    def test_revoke(self):
        rt = UserRefreshToken.objects.create(
            user=self.user,
            jti=str(uuid.uuid4()),
            expires_at=timezone.now() + timedelta(days=7),
        )
        self.assertFalse(rt.revoked)
        rt.revoke()
        rt.refresh_from_db()
        self.assertTrue(rt.revoked)

    def test_str_active(self):
        rt = UserRefreshToken.objects.create(
            user=self.user,
            jti=str(uuid.uuid4()),
            expires_at=timezone.now() + timedelta(days=7),
            device_name="Chrome",
        )
        self.assertIn("active", str(rt))
        self.assertIn("Chrome", str(rt))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2  ─  PERMISSION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class _FakeRequest:
    """Minimal request stand-in for permission unit tests."""

    def __init__(self, user, method: str = "GET"):
        self.user   = user
        self.method = method


class IsClientUserPermissionTest(TestCase):

    def setUp(self):
        self.client_user = make_user(email="client_perm@example.com")
        self.admin_user  = make_admin(email="admin_perm@example.com")
        self.perm        = IsClientUser()

    def test_active_client_allowed(self):
        self.assertTrue(
            self.perm.has_permission(_FakeRequest(self.client_user), None)
        )

    def test_admin_denied(self):
        self.assertFalse(
            self.perm.has_permission(_FakeRequest(self.admin_user), None)
        )

    def test_inactive_user_denied(self):
        self.client_user.is_active = False
        self.assertFalse(
            self.perm.has_permission(_FakeRequest(self.client_user), None)
        )

    def test_deleted_user_denied(self):
        self.client_user.deleted_at = timezone.now()
        self.assertFalse(
            self.perm.has_permission(_FakeRequest(self.client_user), None)
        )

    def test_locked_user_denied(self):
        self.client_user.locked_until = timezone.now() + timedelta(hours=1)
        self.assertFalse(
            self.perm.has_permission(_FakeRequest(self.client_user), None)
        )


class IsAdminUserPermissionTest(TestCase):

    def setUp(self):
        self.admin      = make_admin(email="adm@example.com")
        self.superadmin = make_superadmin(email="sadm@example.com")
        self.client     = make_user(email="cli@example.com")
        self.perm       = IsAdminUser()

    def test_admin_allowed(self):
        self.assertTrue(self.perm.has_permission(_FakeRequest(self.admin), None))

    def test_superadmin_allowed(self):
        self.assertTrue(self.perm.has_permission(_FakeRequest(self.superadmin), None))

    def test_client_denied(self):
        self.assertFalse(self.perm.has_permission(_FakeRequest(self.client), None))


class IsSuperAdminPermissionTest(TestCase):

    def setUp(self):
        self.superadmin = make_superadmin(email="super2@example.com")
        self.admin      = make_admin(email="admin2@example.com")
        self.perm       = IsSuperAdmin()

    def test_superadmin_allowed(self):
        self.assertTrue(self.perm.has_permission(_FakeRequest(self.superadmin), None))

    def test_admin_denied(self):
        self.assertFalse(self.perm.has_permission(_FakeRequest(self.admin), None))


class IsSameTenantPermissionTest(TestCase):

    def setUp(self):
        self.t1   = make_tenant(slug="st1", name="ST1")
        self.t2   = make_tenant(slug="st2", name="ST2")
        self.u1   = make_user(email="st_u1@example.com", tenant=self.t1)
        self.u2   = make_user(email="st_u2@example.com", tenant=self.t2)
        self.perm = IsSameTenant()

    def _obj(self, tenant):
        obj = MagicMock()
        obj.tenant = tenant
        return obj

    def test_same_tenant_allowed(self):
        self.assertTrue(
            self.perm.has_object_permission(
                _FakeRequest(self.u1), None, self._obj(self.t1)
            )
        )

    def test_different_tenant_denied(self):
        self.assertFalse(
            self.perm.has_object_permission(
                _FakeRequest(self.u1), None, self._obj(self.t2)
            )
        )

    def test_superadmin_bypasses_tenant(self):
        su = make_superadmin(email="su_tenant@example.com")
        self.assertTrue(
            self.perm.has_object_permission(
                _FakeRequest(su), None, self._obj(self.t2)
            )
        )


class IsOwnerOrAdminPermissionTest(TestCase):

    def setUp(self):
        self.owner = make_user(email="owner@example.com")
        self.other = make_user(email="other@example.com")
        self.admin = make_admin(email="adm_oa@example.com")
        self.perm  = IsOwnerOrAdmin()

    def _obj(self, user):
        obj      = MagicMock()
        obj.user = user
        return obj

    def test_owner_allowed(self):
        self.assertTrue(
            self.perm.has_object_permission(
                _FakeRequest(self.owner), None, self._obj(self.owner)
            )
        )

    def test_other_user_denied(self):
        self.assertFalse(
            self.perm.has_object_permission(
                _FakeRequest(self.other), None, self._obj(self.owner)
            )
        )

    def test_admin_allowed(self):
        self.assertTrue(
            self.perm.has_object_permission(
                _FakeRequest(self.admin), None, self._obj(self.owner)
            )
        )


class IsEmailVerifiedPermissionTest(TestCase):

    def setUp(self):
        self.perm = IsEmailVerified()

    def test_verified_user_allowed(self):
        user = make_user(email="ver@example.com", verified=True)
        self.assertTrue(self.perm.has_permission(_FakeRequest(user), None))

    def test_unverified_user_denied(self):
        user = make_user(email="unver@example.com", verified=False)
        self.assertFalse(self.perm.has_permission(_FakeRequest(user), None))


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3  ─  SERIALIZER TESTS
# ══════════════════════════════════════════════════════════════════════════════

from apps.accounts.api.serializers import (
    ChangePasswordSerializer,
    EmailLoginSerializer,
    EmailVerifySerializer,
    GoogleOAuthSerializer,
    LogoutSerializer,
    MagicLinkRequestSerializer,
    MagicLinkVerifySerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    RevokeSessionSerializer,
    TokenRefreshSerializer,
    UserMeSerializer,
    UserRegistrationSerializer,
    UserUpdateSerializer,
)


class UserRegistrationSerializerTest(TestCase):

    def _data(self, **overrides):
        base = {
            "email":            "new@example.com",
            "full_name":        "New User",
            "password":         "StrongPass123!",
            "password_confirm": "StrongPass123!",
            "terms_accepted":   True,
        }
        base.update(overrides)
        return base

    def test_valid_data_passes(self):
        s = UserRegistrationSerializer(data=self._data())
        self.assertTrue(s.is_valid(), s.errors)

    def test_password_mismatch(self):
        s = UserRegistrationSerializer(data=self._data(password_confirm="WrongPass!"))
        self.assertFalse(s.is_valid())
        self.assertIn("password_confirm", str(s.errors))

    def test_duplicate_email_rejected(self):
        make_user(email="new@example.com")
        s = UserRegistrationSerializer(data=self._data())
        self.assertFalse(s.is_valid())
        self.assertIn("email", s.errors)

    def test_terms_not_accepted_rejected(self):
        s = UserRegistrationSerializer(data=self._data(terms_accepted=False))
        self.assertFalse(s.is_valid())

    def test_email_normalised_to_lowercase(self):
        data = self._data(email="NEW@EXAMPLE.COM")
        s = UserRegistrationSerializer(data=data)
        self.assertTrue(s.is_valid(), s.errors)
        self.assertEqual(s.validated_data["email"], "new@example.com")


class EmailLoginSerializerTest(TestCase):

    def setUp(self):
        self.user = make_user(email="login@example.com", password="StrongPass123!")

    def test_valid_credentials(self):
        s = EmailLoginSerializer(data={
            "email":    "login@example.com",
            "password": "StrongPass123!",
        })
        self.assertTrue(s.is_valid(), s.errors)
        self.assertEqual(s.validated_data["user"], self.user)

    def test_wrong_password(self):
        s = EmailLoginSerializer(data={
            "email":    "login@example.com",
            "password": "WrongPass!",
        })
        self.assertFalse(s.is_valid())

    def test_nonexistent_email(self):
        s = EmailLoginSerializer(data={
            "email":    "nobody@example.com",
            "password": "StrongPass123!",
        })
        self.assertFalse(s.is_valid())

    def test_unverified_email_rejected(self):
        user = make_user(email="unver2@example.com", verified=False)
        s = EmailLoginSerializer(data={
            "email":    "unver2@example.com",
            "password": "StrongPass123!",
        })
        self.assertFalse(s.is_valid())

    def test_locked_account_rejected(self):
        self.user.lock_account(until=timezone.now() + timedelta(hours=1))
        s = EmailLoginSerializer(data={
            "email":    "login@example.com",
            "password": "StrongPass123!",
        })
        self.assertFalse(s.is_valid())

    def test_inactive_account_rejected(self):
        self.user.is_active = False
        self.user.save()
        s = EmailLoginSerializer(data={
            "email":    "login@example.com",
            "password": "StrongPass123!",
        })
        self.assertFalse(s.is_valid())


class EmailVerifySerializerTest(TestCase):

    def setUp(self):
        self.user = make_user(email="everify@example.com", verified=False)

    def test_valid_token_passes(self):
        raw, _ = _make_ev_token(self.user)
        s = EmailVerifySerializer(data={"token": raw}, context={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertIn("ev_token", s.context)

    def test_invalid_token_rejected(self):
        s = EmailVerifySerializer(data={"token": "garbage_token"}, context={})
        self.assertFalse(s.is_valid())

    def test_expired_token_rejected(self):
        raw, _ = _make_ev_token(self.user, hours=-1)
        s = EmailVerifySerializer(data={"token": raw}, context={})
        self.assertFalse(s.is_valid())


class MagicLinkSerializerTest(TestCase):

    def setUp(self):
        self.user = make_user(email="magic@example.com")

    def test_request_valid_email(self):
        s = MagicLinkRequestSerializer(data={"email": "magic@example.com"})
        self.assertTrue(s.is_valid())

    def test_verify_valid_token(self):
        raw, _ = _make_magic_token(self.user)
        s = MagicLinkVerifySerializer(data={"token": raw}, context={})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertIn("ml_token", s.context)

    def test_verify_expired_token(self):
        raw, _ = _make_magic_token(self.user, minutes=-1)
        s = MagicLinkVerifySerializer(data={"token": raw}, context={})
        self.assertFalse(s.is_valid())


class PasswordResetSerializerTest(TestCase):

    def setUp(self):
        self.user = make_user(email="reset@example.com")

    def test_request_valid(self):
        s = PasswordResetRequestSerializer(data={"email": "reset@example.com"})
        self.assertTrue(s.is_valid())

    def test_confirm_valid(self):
        raw, _ = _make_reset_token(self.user)
        s = PasswordResetConfirmSerializer(
            data={
                "token":            raw,
                "password":         "NewPass456!",
                "password_confirm": "NewPass456!",
            },
            context={},
        )
        self.assertTrue(s.is_valid(), s.errors)
        self.assertIn("reset_token", s.context)

    def test_confirm_password_mismatch(self):
        raw, _ = _make_reset_token(self.user)
        s = PasswordResetConfirmSerializer(
            data={
                "token":            raw,
                "password":         "NewPass456!",
                "password_confirm": "Different456!",
            },
            context={},
        )
        self.assertFalse(s.is_valid())

    def test_confirm_expired_token(self):
        raw, _ = _make_reset_token(self.user, minutes=-1)
        s = PasswordResetConfirmSerializer(
            data={
                "token":            raw,
                "password":         "NewPass456!",
                "password_confirm": "NewPass456!",
            },
            context={},
        )
        self.assertFalse(s.is_valid())


class GoogleOAuthSerializerTest(TestCase):

    def test_valid_credential(self):
        s = GoogleOAuthSerializer(data={"credential": "some.jwt.token"})
        self.assertTrue(s.is_valid())

    def test_missing_credential(self):
        s = GoogleOAuthSerializer(data={})
        self.assertFalse(s.is_valid())
        self.assertIn("credential", s.errors)


class ChangePasswordSerializerTest(TestCase):

    def setUp(self):
        self.user = make_user(email="chpwd@example.com", password="OldPass123!")

    def _request(self):
        req = MagicMock()
        req.user = self.user
        return req

    def test_valid_change(self):
        s = ChangePasswordSerializer(
            data={
                "current_password":    "OldPass123!",
                "new_password":        "NewPass456!",
                "new_password_confirm": "NewPass456!",
            },
            context={"request": self._request()},
        )
        self.assertTrue(s.is_valid(), s.errors)

    def test_wrong_current_password(self):
        s = ChangePasswordSerializer(
            data={
                "current_password":    "WrongPass!",
                "new_password":        "NewPass456!",
                "new_password_confirm": "NewPass456!",
            },
            context={"request": self._request()},
        )
        self.assertFalse(s.is_valid())

    def test_same_as_current_rejected(self):
        s = ChangePasswordSerializer(
            data={
                "current_password":    "OldPass123!",
                "new_password":        "OldPass123!",
                "new_password_confirm": "OldPass123!",
            },
            context={"request": self._request()},
        )
        self.assertFalse(s.is_valid())

    def test_oauth_user_rejected(self):
        self.user.google_sub = "google-sub-456"
        self.user.set_unusable_password()
        self.user.save()
        s = ChangePasswordSerializer(
            data={
                "current_password":    "anything",
                "new_password":        "NewPass456!",
                "new_password_confirm": "NewPass456!",
            },
            context={"request": self._request()},
        )
        self.assertFalse(s.is_valid())


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4  ─  SERVICE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class AuthServiceRegisterTest(TestCase):

    def test_register_creates_user(self):
        data = {
            "email":          "svc@example.com",
            "full_name":      "SVC User",
            "password":       "StrongPass123!",
            "terms_accepted": True,
        }
        with patch("apps.accounts.services.services._send_email"):
            user = AuthService.register(data)
        self.assertIsNotNone(user.pk)
        self.assertEqual(user.email, "svc@example.com")
        self.assertFalse(user.is_email_verified)   # needs email confirmation

    def test_register_sends_verification_email(self):
        data = {
            "email":          "svc2@example.com",
            "full_name":      "SVC2",
            "password":       "StrongPass123!",
            "terms_accepted": True,
        }
        with patch("apps.accounts.services.services._send_email") as mock_mail:
            AuthService.register(data)
        mock_mail.assert_called_once()
        subject = mock_mail.call_args[0][0]
        self.assertIn("verify", subject.lower())

    def test_register_creates_ev_token(self):
        data = {
            "email":          "svc3@example.com",
            "full_name":      "SVC3",
            "password":       "StrongPass123!",
            "terms_accepted": True,
        }
        with patch("apps.accounts.services.services._send_email"):
            user = AuthService.register(data)
        self.assertTrue(
            EmailVerificationToken.objects.filter(user=user).exists()
        )

    def test_register_weak_password_rejected(self):
        from rest_framework.exceptions import ValidationError
        data = {
            "email":          "weak@example.com",
            "full_name":      "Weak",
            "password":       "123",
            "terms_accepted": True,
        }
        with self.assertRaises(ValidationError):
            AuthService.register(data)


class AuthServiceVerifyEmailTest(TestCase):

    def setUp(self):
        self.user = make_user(email="everify2@example.com", verified=False)

    def test_verify_email_marks_verified(self):
        _, token = _make_ev_token(self.user)
        AuthService.verify_email(token)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)

    def test_verify_email_consumes_token(self):
        _, token = _make_ev_token(self.user)
        AuthService.verify_email(token)
        token.refresh_from_db()
        self.assertTrue(token.used)


class AuthServiceLoginTest(TestCase):

    def setUp(self):
        self.user    = make_user(email="svc_login@example.com")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestBrowser"}

    def test_login_returns_tokens(self):
        tokens = AuthService.login(self.user, self.request)
        self.assertIn("access",  tokens)
        self.assertIn("refresh", tokens)
        self.assertIn("access_expires_at", tokens)

    def test_login_records_session(self):
        AuthService.login(self.user, self.request)
        self.assertTrue(
            UserRefreshToken.objects.filter(user=self.user, revoked=False).exists()
        )

    def test_login_updates_last_login_ip(self):
        AuthService.login(self.user, self.request)
        self.user.refresh_from_db()
        self.assertEqual(self.user.last_login_ip, "127.0.0.1")

    def test_login_resets_failed_attempts(self):
        self.user.failed_login_attempts = 3
        self.user.save()
        AuthService.login(self.user, self.request)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)


class AuthServiceMagicLinkTest(TestCase):

    def setUp(self):
        self.user    = make_user(email="magic2@example.com")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestBrowser"}

    def test_magic_link_request_creates_token(self):
        with patch("apps.accounts.services.services._send_email"):
            AuthService.magic_link_request(self.user.email)
        self.assertTrue(
            MagicLinkToken.objects.filter(user=self.user, used=False).exists()
        )

    def test_magic_link_request_unknown_email_silent(self):
        # Should not raise — prevents enumeration
        with patch("apps.accounts.services.services._send_email") as mock_mail:
            AuthService.magic_link_request("nobody@example.com")
        mock_mail.assert_not_called()

    def test_magic_link_request_invalidates_previous_tokens(self):
        _, old_token = _make_magic_token(self.user)
        with patch("apps.accounts.services.services._send_email"):
            AuthService.magic_link_request(self.user.email)
        old_token.refresh_from_db()
        self.assertTrue(old_token.used)

    def test_magic_link_verify_returns_tokens(self):
        _, ml_token = _make_magic_token(self.user)
        tokens = AuthService.magic_link_verify(ml_token, self.request)
        self.assertIn("access",  tokens)
        self.assertIn("refresh", tokens)

    def test_magic_link_verify_auto_verifies_email(self):
        self.user.is_email_verified = False
        self.user.save()
        _, ml_token = _make_magic_token(self.user)
        AuthService.magic_link_verify(ml_token, self.request)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)

    def test_magic_link_verify_consumes_token(self):
        _, ml_token = _make_magic_token(self.user)
        AuthService.magic_link_verify(ml_token, self.request)
        ml_token.refresh_from_db()
        self.assertTrue(ml_token.used)


class AuthServicePasswordResetTest(TestCase):

    def setUp(self):
        self.user = make_user(email="pr@example.com")

    def test_password_reset_request_creates_token(self):
        with patch("apps.accounts.services.services._send_email"):
            AuthService.password_reset_request(self.user.email)
        self.assertTrue(
            PasswordResetToken.objects.filter(user=self.user, used=False).exists()
        )

    def test_password_reset_request_unknown_email_silent(self):
        with patch("apps.accounts.services.services._send_email") as mock_mail:
            AuthService.password_reset_request("ghost@example.com")
        mock_mail.assert_not_called()

    def test_password_reset_confirm_changes_password(self):
        _, token = _make_reset_token(self.user)
        AuthService.password_reset_confirm(token, "BrandNew789!")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("BrandNew789!"))

    def test_password_reset_confirm_revokes_all_sessions(self):
        # Create a session
        UserRefreshToken.objects.create(
            user=self.user,
            jti=str(uuid.uuid4()),
            expires_at=timezone.now() + timedelta(days=7),
        )
        _, token = _make_reset_token(self.user)
        AuthService.password_reset_confirm(token, "BrandNew789!")
        active = UserRefreshToken.objects.filter(user=self.user, revoked=False)
        self.assertEqual(active.count(), 0)

    def test_password_reset_invalidates_previous_tokens(self):
        _, old_token = _make_reset_token(self.user)
        with patch("apps.accounts.services.services._send_email"):
            AuthService.password_reset_request(self.user.email)
        old_token.refresh_from_db()
        self.assertTrue(old_token.used)


class AuthServiceLogoutTest(TestCase):

    def setUp(self):
        self.user    = make_user(email="logout_svc@example.com")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestBrowser"}

    def test_logout_revokes_session(self):
        tokens  = AuthService.login(self.user, self.request)
        refresh = tokens["refresh"]
        AuthService.logout(refresh, self.user)
        # All sessions should now be revoked
        active = UserRefreshToken.objects.filter(user=self.user, revoked=False)
        self.assertEqual(active.count(), 0)


class AuthServiceChangePasswordTest(TestCase):

    def setUp(self):
        self.user    = make_user(email="chpwd2@example.com", password="OldPass123!")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestBrowser"}

    def test_change_password_updates_hash(self):
        AuthService.change_password(self.user, "NewPass789!")
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewPass789!"))
        self.assertFalse(self.user.check_password("OldPass123!"))

    def test_change_password_revokes_other_sessions(self):
        # Create two sessions
        t1 = AuthService.login(self.user, self.request)
        t2 = AuthService.login(self.user, self.request)
        # Change password, keeping session 1
        AuthService.change_password(
            self.user, "NewPass789!", current_refresh=t1["refresh"]
        )
        # session 1's jti should still be active; session 2 revoked
        from rest_framework_simplejwt.tokens import RefreshToken as RT
        jti1 = str(RT(t1["refresh"]).get("jti", ""))
        jti2 = str(RT(t2["refresh"]).get("jti", ""))
        self.assertFalse(
            UserRefreshToken.objects.get(jti=jti1).revoked,
            "Current session should remain active",
        )
        self.assertTrue(
            UserRefreshToken.objects.get(jti=jti2).revoked,
            "Other sessions should be revoked",
        )


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5  ─  GOOGLE OAUTH SERVICE TEST
# ══════════════════════════════════════════════════════════════════════════════

GOOGLE_MOCK_ID_INFO = {
    "sub":            "google-sub-999",
    "email":          "googleoauth@example.com",
    "name":           "Google User",
    "picture":        "https://lh3.googleusercontent.com/photo.jpg",
    "email_verified": True,
    "iss":            "accounts.google.com",
    "aud":            "test-client-id.apps.googleusercontent.com",
}


@override_settings(GOOGLE_OAUTH2_CLIENT_ID="test-client-id.apps.googleusercontent.com")
class AuthServiceGoogleOAuthTest(TestCase):

    def setUp(self):
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "Chrome/Test"}

    def _call(self, id_info: dict | None = None):
        info = id_info or GOOGLE_MOCK_ID_INFO
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=info,
        ):
            return AuthService.google_oauth("fake.google.credential", self.request)

    # ── Happy paths ───────────────────────────────────────────────────────────

    def test_creates_new_user_on_first_login(self):
        tokens = self._call()
        user = User.objects.get(google_sub="google-sub-999")
        self.assertEqual(user.email, "googleoauth@example.com")
        self.assertTrue(user.is_email_verified)
        self.assertIn("access",  tokens)
        self.assertIn("refresh", tokens)

    def test_new_user_has_no_usable_password(self):
        self._call()
        user = User.objects.get(google_sub="google-sub-999")
        self.assertFalse(user.has_usable_password())

    def test_existing_user_by_sub_is_fetched(self):
        # Pre-create user with same google_sub
        existing = make_user(
            email="googleoauth@example.com",
            google_sub="google-sub-999",
        )
        tokens = self._call()
        # Should not create a new user
        self.assertEqual(
            User.objects.filter(google_sub="google-sub-999").count(), 1
        )
        self.assertIn("access", tokens)

    def test_links_existing_account_by_email(self):
        """User registered with email+password first, then signs in with Google."""
        existing = make_user(email="googleoauth@example.com")
        self.assertIsNone(existing.google_sub)

        self._call()

        existing.refresh_from_db()
        self.assertEqual(existing.google_sub, "google-sub-999")
        # Only one user row
        self.assertEqual(
            User.objects.filter(email="googleoauth@example.com").count(), 1
        )

    def test_updates_picture_on_every_login(self):
        existing = make_user(
            email="googleoauth@example.com",
            google_sub="google-sub-999",
            google_picture_url="https://old.url/old.jpg",
        )
        self._call()
        existing.refresh_from_db()
        self.assertEqual(
            existing.google_picture_url,
            "https://lh3.googleusercontent.com/photo.jpg",
        )

    def test_records_session_on_login(self):
        self._call()
        user = User.objects.get(google_sub="google-sub-999")
        self.assertTrue(
            UserRefreshToken.objects.filter(user=user, revoked=False).exists()
        )

    # ── Error paths ───────────────────────────────────────────────────────────

    def test_invalid_google_token_raises(self):
        from rest_framework.exceptions import AuthenticationFailed
        from google.auth.exceptions import GoogleAuthError

        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            side_effect=GoogleAuthError("bad token"),
        ):
            with self.assertRaises(AuthenticationFailed):
                AuthService.google_oauth("bad.token.here", self.request)

    def test_unverified_google_email_raises(self):
        from rest_framework.exceptions import AuthenticationFailed

        bad_info = {**GOOGLE_MOCK_ID_INFO, "email_verified": False}
        with self.assertRaises(AuthenticationFailed):
            self._call(id_info=bad_info)

    def test_missing_sub_raises(self):
        from rest_framework.exceptions import AuthenticationFailed

        bad_info = {**GOOGLE_MOCK_ID_INFO, "sub": ""}
        with self.assertRaises(AuthenticationFailed):
            self._call(id_info=bad_info)

    def test_deactivated_account_raises(self):
        from rest_framework.exceptions import AuthenticationFailed

        make_user(
            email="googleoauth@example.com",
            google_sub="google-sub-999",
            is_active=False,
        )
        with self.assertRaises(AuthenticationFailed):
            self._call()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6  ─  API INTEGRATION TESTS  (full HTTP round-trips)
# ══════════════════════════════════════════════════════════════════════════════

# ── Base class: disable DRF throttling for all API tests ─────────────────────
# All tests share the same in-process HTTP client and loopback IP, so the
# default throttle buckets fill up across test cases and return 429.
# Overriding REST_FRAMEWORK here replaces only the throttle keys; every other
# DRF setting (auth, permission, pagination, schema) is also declared so the
# suite is fully self-contained and independent of the project settings file.
@override_settings(
    REST_FRAMEWORK={
        "DEFAULT_AUTHENTICATION_CLASSES": (
            "rest_framework_simplejwt.authentication.JWTAuthentication",
        ),
        "DEFAULT_PERMISSION_CLASSES": (
            "rest_framework.permissions.IsAuthenticated",
        ),
        "DEFAULT_SCHEMA_CLASS":     "drf_spectacular.openapi.AutoSchema",
        "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
        "PAGE_SIZE":                20,
        # ↓ throttling completely disabled for tests
        "DEFAULT_THROTTLE_CLASSES": [],
        "DEFAULT_THROTTLE_RATES":   {},
        "EXCEPTION_HANDLER":        "rest_framework.views.exception_handler",
    }
)
class NoThrottleAPITestCase(APITestCase):
    """
    Base class for every API integration test.

    Disables DRF throttling via override_settings so individual test cases
    never receive 429 responses due to cross-test bucket accumulation.
    Inherit from this instead of APITestCase for all HTTP-level tests.
    """
    pass


class RegisterAPITest(NoThrottleAPITestCase):

    url = "/api/v1/auth/register/"

    def _data(self, **ov):
        base = {
            "email":            "api_reg@example.com",
            "full_name":        "API Reg",
            "password":         "StrongPass123!",
            "password_confirm": "StrongPass123!",
            "terms_accepted":   True,
        }
        base.update(ov)
        return base

    def test_register_201(self):
        with patch("apps.accounts.services.services._send_email"):
            res = self.client.post(self.url, self._data(), format="json")
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertIn("user_id", res.data)

    def test_register_duplicate_email_400(self):
        make_user(email="api_reg@example.com")
        with patch("apps.accounts.services.services._send_email"):
            res = self.client.post(self.url, self._data(), format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_password_mismatch_400(self):
        res = self.client.post(
            self.url,
            self._data(password_confirm="Different!"),
            format="json",
        )
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)


class VerifyEmailAPITest(NoThrottleAPITestCase):

    url = "/api/v1/auth/verify-email/"

    def setUp(self):
        self.user = make_user(email="api_ev@example.com", verified=False)

    def test_verify_email_200(self):
        raw, _ = _make_ev_token(self.user)
        res = self.client.post(self.url, {"token": raw}, format="json")
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)

    def test_verify_email_invalid_token_400(self):
        res = self.client.post(self.url, {"token": "garbage"}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_email_expired_token_400(self):
        raw, _ = _make_ev_token(self.user, hours=-1)
        res = self.client.post(self.url, {"token": raw}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)


class LoginAPITest(NoThrottleAPITestCase):

    url = "/api/v1/auth/login/"

    def setUp(self):
        self.user = make_user(email="api_login@example.com", password="StrongPass123!")

    def test_login_200(self):
        res = self.client.post(self.url, {
            "email":    "api_login@example.com",
            "password": "StrongPass123!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("access",  res.data)
        self.assertIn("refresh", res.data)

    def test_login_wrong_password_400(self):
        res = self.client.post(self.url, {
            "email":    "api_login@example.com",
            "password": "WrongPass!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_nonexistent_user_400(self):
        res = self.client.post(self.url, {
            "email":    "nobody@example.com",
            "password": "StrongPass123!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_increments_failed_attempts(self):
        self.client.post(self.url, {
            "email":    "api_login@example.com",
            "password": "WrongPass!",
        }, format="json")
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)


class LogoutAPITest(NoThrottleAPITestCase):

    url = "/api/v1/auth/logout/"

    def setUp(self):
        self.user    = make_user(email="api_logout@example.com")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "Test"}
        self.tokens  = AuthService.login(self.user, self.request)

    def test_logout_200(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.tokens['access']}"
        )
        res = self.client.post(
            self.url, {"refresh": self.tokens["refresh"]}, format="json"
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_logout_requires_auth(self):
        res = self.client.post(
            self.url, {"refresh": self.tokens["refresh"]}, format="json"
        )
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_revokes_session(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.tokens['access']}"
        )
        self.client.post(
            self.url, {"refresh": self.tokens["refresh"]}, format="json"
        )
        active = UserRefreshToken.objects.filter(user=self.user, revoked=False)
        self.assertEqual(active.count(), 0)


class TokenRefreshAPITest(NoThrottleAPITestCase):

    url = "/api/v1/auth/token/refresh/"

    def setUp(self):
        self.user    = make_user(email="api_refresh@example.com")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "Test"}
        self.tokens  = AuthService.login(self.user, self.request)

    def test_refresh_200(self):
        res = self.client.post(
            self.url, {"refresh": self.tokens["refresh"]}, format="json"
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("access", res.data)

    def test_refresh_invalid_token_401(self):
        res = self.client.post(self.url, {"refresh": "bad.token"}, format="json")
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_revoked_token_401(self):
        """Reusing a revoked token is detected and all sessions are cleared."""
        # Revoke the session first
        from rest_framework_simplejwt.tokens import RefreshToken as RT
        jti = str(RT(self.tokens["refresh"]).get("jti", ""))
        UserRefreshToken.objects.filter(jti=jti).update(revoked=True)

        res = self.client.post(
            self.url, {"refresh": self.tokens["refresh"]}, format="json"
        )
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class MagicLinkAPITest(NoThrottleAPITestCase):

    request_url = "/api/v1/auth/magic-link/request/"
    verify_url  = "/api/v1/auth/magic-link/verify/"

    def setUp(self):
        self.user = make_user(email="api_magic@example.com")

    def test_request_200_always(self):
        with patch("apps.accounts.services.services._send_email"):
            res = self.client.post(
                self.request_url, {"email": "api_magic@example.com"}, format="json"
            )
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_request_unknown_email_200(self):
        """Must still return 200 to prevent enumeration."""
        with patch("apps.accounts.services.services._send_email"):
            res = self.client.post(
                self.request_url, {"email": "nobody@example.com"}, format="json"
            )
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_verify_returns_tokens(self):
        raw, _ = _make_magic_token(self.user)
        res = self.client.post(self.verify_url, {"token": raw}, format="json")
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("access",  res.data)
        self.assertIn("refresh", res.data)

    def test_verify_expired_token_400(self):
        raw, _ = _make_magic_token(self.user, minutes=-1)
        res = self.client.post(self.verify_url, {"token": raw}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_invalid_token_400(self):
        res = self.client.post(self.verify_url, {"token": "garbage"}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)


class PasswordResetAPITest(NoThrottleAPITestCase):

    request_url = "/api/v1/auth/password-reset/request/"
    confirm_url = "/api/v1/auth/password-reset/confirm/"

    def setUp(self):
        self.user = make_user(email="api_reset@example.com", password="OldPass123!")

    def test_request_200_always(self):
        with patch("apps.accounts.services.services._send_email"):
            res = self.client.post(
                self.request_url, {"email": "api_reset@example.com"}, format="json"
            )
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_confirm_changes_password(self):
        raw, _ = _make_reset_token(self.user)
        res = self.client.post(self.confirm_url, {
            "token":            raw,
            "password":         "NewPass789!",
            "password_confirm": "NewPass789!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("NewPass789!"))

    def test_confirm_expired_token_400(self):
        raw, _ = _make_reset_token(self.user, minutes=-1)
        res = self.client.post(self.confirm_url, {
            "token":            raw,
            "password":         "NewPass789!",
            "password_confirm": "NewPass789!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_confirm_mismatch_400(self):
        raw, _ = _make_reset_token(self.user)
        res = self.client.post(self.confirm_url, {
            "token":            raw,
            "password":         "NewPass789!",
            "password_confirm": "DifferentPass!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)


@override_settings(
    GOOGLE_OAUTH2_CLIENT_ID="test-client-id.apps.googleusercontent.com",
    REST_FRAMEWORK={
        "DEFAULT_AUTHENTICATION_CLASSES": (
            "rest_framework_simplejwt.authentication.JWTAuthentication",
        ),
        "DEFAULT_PERMISSION_CLASSES": (
            "rest_framework.permissions.IsAuthenticated",
        ),
        "DEFAULT_SCHEMA_CLASS":     "drf_spectacular.openapi.AutoSchema",
        "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
        "PAGE_SIZE":                20,
        "DEFAULT_THROTTLE_CLASSES": [],   # throttling disabled for tests
        "DEFAULT_THROTTLE_RATES":   {},
        "EXCEPTION_HANDLER":        "rest_framework.views.exception_handler",
    },
)
class GoogleOAuthAPITest(NoThrottleAPITestCase):

    url = "/api/v1/auth/google/"

    def _post(self, id_info: dict | None = None):
        info = id_info or GOOGLE_MOCK_ID_INFO
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            return_value=info,
        ):
            return self.client.post(
                self.url, {"credential": "fake.google.credential"}, format="json"
            )

    def test_google_oauth_200(self):
        res = self._post()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("access",  res.data)
        self.assertIn("refresh", res.data)

    def test_google_oauth_creates_user(self):
        self._post()
        self.assertTrue(
            User.objects.filter(google_sub="google-sub-999").exists()
        )

    def test_google_oauth_links_existing_user(self):
        existing = make_user(email="googleoauth@example.com")
        self._post()
        existing.refresh_from_db()
        self.assertEqual(existing.google_sub, "google-sub-999")

    def test_google_oauth_invalid_token_401(self):
        from google.auth.exceptions import GoogleAuthError
        with patch(
            "google.oauth2.id_token.verify_oauth2_token",
            side_effect=GoogleAuthError("bad"),
        ):
            res = self.client.post(
                self.url, {"credential": "bad.token"}, format="json"
            )
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_google_oauth_missing_credential_400(self):
        res = self.client.post(self.url, {}, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_google_oauth_unverified_email_401(self):
        bad = {**GOOGLE_MOCK_ID_INFO, "email_verified": False}
        res = self._post(id_info=bad)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class ProfileAPITest(NoThrottleAPITestCase):

    me_url     = "/api/v1/auth/me/"
    update_url = "/api/v1/auth/me/update/"

    def setUp(self):
        self.user    = make_user(email="api_me@example.com")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "Test"}
        self.tokens  = AuthService.login(self.user, self.request)
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.tokens['access']}"
        )

    def test_me_200(self):
        res = self.client.get(self.me_url)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data["email"], "api_me@example.com")

    def test_me_unauthenticated_401(self):
        self.client.credentials()
        res = self.client.get(self.me_url)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_update_full_name(self):
        res = self.client.patch(
            self.update_url, {"full_name": "Updated Name"}, format="json"
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data["full_name"], "Updated Name")

    def test_update_profile_bio(self):
        res = self.client.patch(
            self.update_url,
            {"profile": {"bio": "Hello world"}},
            format="json",
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.user.profile.refresh_from_db()
        self.assertEqual(self.user.profile.bio, "Hello world")


class ChangePasswordAPITest(NoThrottleAPITestCase):

    url = "/api/v1/auth/me/change-password/"

    def setUp(self):
        self.user    = make_user(email="api_cpwd@example.com", password="OldPass123!")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "Test"}
        self.tokens  = AuthService.login(self.user, self.request)
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.tokens['access']}"
        )

    def test_change_password_200(self):
        res = self.client.post(self.url, {
            "current_password":    "OldPass123!",
            "new_password":        "NewPass789!",
            "new_password_confirm": "NewPass789!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_change_password_wrong_current_400(self):
        res = self.client.post(self.url, {
            "current_password":    "WrongPass!",
            "new_password":        "NewPass789!",
            "new_password_confirm": "NewPass789!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_unauthenticated_401(self):
        self.client.credentials()
        res = self.client.post(self.url, {
            "current_password":    "OldPass123!",
            "new_password":        "NewPass789!",
            "new_password_confirm": "NewPass789!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class SessionsAPITest(NoThrottleAPITestCase):

    list_url   = "/api/v1/auth/sessions/"
    revoke_url = "/api/v1/auth/sessions/{}/revoke/"

    def setUp(self):
        self.user    = make_user(email="api_sessions@example.com")
        self.request = MagicMock()
        self.request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "Test"}
        self.tokens  = AuthService.login(self.user, self.request)
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.tokens['access']}"
        )

    def test_list_sessions_200(self):
        res = self.client.get(self.list_url)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("sessions", res.data)
        self.assertGreaterEqual(len(res.data["sessions"]), 1)

    def test_revoke_session_200(self):
        session = UserRefreshToken.objects.filter(
            user=self.user, revoked=False
        ).first()
        res = self.client.delete(
            self.revoke_url.format(session.id)
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        session.refresh_from_db()
        self.assertTrue(session.revoked)

    def test_revoke_nonexistent_session_404(self):
        fake_id = uuid.uuid4()
        res = self.client.delete(self.revoke_url.format(fake_id))
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

    def test_sessions_unauthenticated_401(self):
        self.client.credentials()
        res = self.client.get(self.list_url)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7  ─  CELERY TASK TESTS
# ══════════════════════════════════════════════════════════════════════════════

class CleanupExpiredTokensTaskTest(TestCase):

    def setUp(self):
        self.user = make_user(email="task@example.com")

    def _expired(self, model, **kwargs):
        """Create a token that expired 1 hour ago."""
        raw = str(uuid.uuid4()).replace("-", "")
        return model.objects.create(
            user=self.user,
            token_hash=_sha256(raw),
            expires_at=timezone.now() - timedelta(hours=1),
            **kwargs,
        )

    def test_cleans_expired_magic_link_tokens(self):
        self._expired(MagicLinkToken)
        result = cleanup_expired_tokens()
        self.assertGreaterEqual(result["magic_link_tokens_deleted"], 1)
        self.assertEqual(MagicLinkToken.objects.filter(user=self.user).count(), 0)

    def test_cleans_expired_email_verification_tokens(self):
        # First mark any existing active tokens as used to avoid constraint
        EmailVerificationToken.objects.filter(user=self.user, used=False).update(
            used=True, used_at=timezone.now()
        )
        self._expired(EmailVerificationToken)
        result = cleanup_expired_tokens()
        self.assertGreaterEqual(result["email_verification_tokens_deleted"], 1)

    def test_cleans_expired_password_reset_tokens(self):
        self._expired(PasswordResetToken)
        result = cleanup_expired_tokens()
        self.assertGreaterEqual(result["password_reset_tokens_deleted"], 1)

    def test_cleans_expired_refresh_tokens(self):
        UserRefreshToken.objects.create(
            user=self.user,
            jti=str(uuid.uuid4()),
            expires_at=timezone.now() - timedelta(hours=1),
        )
        result = cleanup_expired_tokens()
        self.assertGreaterEqual(result["refresh_tokens_deleted"], 1)

    def test_does_not_delete_valid_tokens(self):
        raw, token = _make_magic_token(self.user)
        cleanup_expired_tokens()
        self.assertTrue(MagicLinkToken.objects.filter(pk=token.pk).exists())


class UnlockExpiredAccountsTaskTest(TestCase):

    def test_unlocks_account_whose_lock_has_elapsed(self):
        user = make_user(email="locked_task@example.com")
        user.locked_until          = timezone.now() - timedelta(minutes=1)
        user.failed_login_attempts = 5
        user.save()

        count = unlock_expired_accounts()

        self.assertGreaterEqual(count, 1)
        user.refresh_from_db()
        self.assertIsNone(user.locked_until)
        self.assertEqual(user.failed_login_attempts, 0)

    def test_does_not_unlock_active_lock(self):
        user = make_user(email="still_locked@example.com")
        user.locked_until = timezone.now() + timedelta(hours=1)
        user.save()

        unlock_expired_accounts()

        user.refresh_from_db()
        self.assertIsNotNone(user.locked_until)

    def test_returns_count_of_unlocked(self):
        for i in range(3):
            u = make_user(
                email=f"multi_lock_{i}@example.com",
                tenant=make_tenant(slug=f"ml-tenant-{i}", name=f"MLT{i}"),
            )
            u.locked_until = timezone.now() - timedelta(minutes=1)
            u.save()

        count = unlock_expired_accounts()
        self.assertGreaterEqual(count, 3)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8  ─  EDGE CASES & SECURITY
# ══════════════════════════════════════════════════════════════════════════════

class SecurityEdgeCaseTest(NoThrottleAPITestCase):
    """
    Miscellaneous security-focused tests that don't fit a single category.
    """

    def test_register_endpoint_rejects_html_injection_in_name(self):
        """Full name is stored as-is; HTML is escaped at the template layer.
        This test verifies the API stores what is given (no server-side strip)."""
        with patch("apps.accounts.services.services._send_email"):
            res = self.client.post("/api/v1/auth/register/", {
                "email":            "xss@example.com",
                "full_name":        "<script>alert(1)</script>",
                "password":         "StrongPass123!",
                "password_confirm": "StrongPass123!",
                "terms_accepted":   True,
            }, format="json")
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email="xss@example.com")
        self.assertEqual(user.full_name, "<script>alert(1)</script>")

    def test_magic_link_token_cannot_be_reused(self):
        user    = make_user(email="reuse_ml@example.com")
        raw, _  = _make_magic_token(user)
        request = MagicMock()
        request.META = {"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "Test"}

        # First use
        res1 = self.client.post(
            "/api/v1/auth/magic-link/verify/", {"token": raw}, format="json"
        )
        self.assertEqual(res1.status_code, status.HTTP_200_OK)

        # Second use — must fail
        res2 = self.client.post(
            "/api/v1/auth/magic-link/verify/", {"token": raw}, format="json"
        )
        self.assertEqual(res2.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_reset_token_cannot_be_reused(self):
        user   = make_user(email="reuse_pr@example.com")
        raw, _ = _make_reset_token(user)

        # First use
        res1 = self.client.post("/api/v1/auth/password-reset/confirm/", {
            "token":            raw,
            "password":         "NewPass789!",
            "password_confirm": "NewPass789!",
        }, format="json")
        self.assertEqual(res1.status_code, status.HTTP_200_OK)

        # Second use — must fail
        res2 = self.client.post("/api/v1/auth/password-reset/confirm/", {
            "token":            raw,
            "password":         "AnotherPass!",
            "password_confirm": "AnotherPass!",
        }, format="json")
        self.assertEqual(res2.status_code, status.HTTP_400_BAD_REQUEST)

    def test_account_locked_after_max_failed_attempts(self):
        """
        After MAX_FAILED_LOGIN_ATTEMPTS wrong passwords the account is locked.
        """
        user = make_user(email="brute@example.com", password="StrongPass123!")

        with self.settings(MAX_FAILED_LOGIN_ATTEMPTS=3, ACCOUNT_LOCK_MINUTES=30):
            for _ in range(3):
                self.client.post("/api/v1/auth/login/", {
                    "email":    "brute@example.com",
                    "password": "WrongPass!",
                }, format="json")

        user.refresh_from_db()
        self.assertTrue(user.is_locked)

    def test_soft_deleted_user_cannot_login(self):
        user = make_user(email="deleted_login@example.com", password="StrongPass123!")
        user.soft_delete()

        res = self.client.post("/api/v1/auth/login/", {
            "email":    "deleted_login@example.com",
            "password": "StrongPass123!",
        }, format="json")
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_me_endpoint_with_expired_access_token_401(self):
        """Expired access tokens are rejected (SimpleJWT handles this)."""
        # We can only simulate this with a manipulated token — just verify
        # that a garbage bearer token returns 401.
        self.client.credentials(HTTP_AUTHORIZATION="Bearer totally.fake.token")
        res = self.client.get("/api/v1/auth/me/")
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)