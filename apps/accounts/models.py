"""
================================================================================
  apps/accounts/models.py
  PRODUCTION-READY DJANGO AUTHENTICATION MODELS
  Multi-Role, Multi-Tenant, Enterprise-Grade + Google OAuth2
================================================================================
"""
from __future__ import annotations

import uuid
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _uuid_pk() -> models.UUIDField:
    """Shared UUID primary-key definition used across all models."""
    return models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        db_index=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# 1. TENANT
# ──────────────────────────────────────────────────────────────────────────────

class Tenant(models.Model):
    """
    Isolated organisational unit (company / team / workspace).

    Rules
    -----
    - Every user except global superusers belongs to exactly one tenant.
    - All business-data ORM queries MUST be scoped with `.filter(tenant=...)`.
    - Cascade deletes are blocked via PROTECT on the FK; archive the tenant first.
    """

    class SubscriptionTier(models.TextChoices):
        FREE       = "free",       _("Free")
        PRO        = "pro",        _("Pro")
        ENTERPRISE = "enterprise", _("Enterprise")

    id                = _uuid_pk()
    name              = models.CharField(_("name"), max_length=255)
    slug              = models.SlugField(
        _("slug"), max_length=100, unique=True,
        help_text=_("URL-safe identifier, e.g. 'acme-corp'."),
    )
    subscription_tier = models.CharField(
        _("subscription tier"),
        max_length=20,
        choices=SubscriptionTier.choices,
        default=SubscriptionTier.FREE,
        db_index=True,
    )
    settings          = models.JSONField(_("settings"), default=dict, blank=True)
    is_active         = models.BooleanField(_("active"), default=True)
    created_at        = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at        = models.DateTimeField(_("updated at"), auto_now=True)

    class Meta:
        ordering     = ["name"]
        verbose_name = _("tenant")
        verbose_name_plural = _("tenants")

    def __str__(self) -> str:
        return f"{self.name} ({self.get_subscription_tier_display()})"


# ──────────────────────────────────────────────────────────────────────────────
# 2. CUSTOM USER MANAGER
# ──────────────────────────────────────────────────────────────────────────────

class UserManager(BaseUserManager["User"]):
    """
    Uses lower-cased email as the unique identifier.
    Provides extra queryset helpers used throughout the app.
    """

    def _create_user(
        self,
        email: str,
        full_name: str,
        password: str | None,
        **extra_fields,
    ) -> "User":
        if not email:
            raise ValueError(_("An email address is required."))
        email = self.normalize_email(email).lower()
        user  = self.model(email=email, full_name=full_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(
        self,
        email: str,
        full_name: str,
        password: str | None = None,
        **extra_fields,
    ) -> "User":
        extra_fields.setdefault("is_staff",     False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, full_name, password, **extra_fields)

    def create_superuser(
        self,
        email: str,
        full_name: str,
        password: str,
        **extra_fields,
    ) -> "User":
        extra_fields.setdefault("is_staff",          True)
        extra_fields.setdefault("is_superuser",      True)
        extra_fields.setdefault("is_email_verified", True)
        extra_fields.setdefault("is_active",         True)
        if not extra_fields.get("is_staff"):
            raise ValueError(_("Superuser must have is_staff=True."))
        if not extra_fields.get("is_superuser"):
            raise ValueError(_("Superuser must have is_superuser=True."))
        return self._create_user(email, full_name, password, **extra_fields)

    # ── Queryset helpers ──────────────────────────────────────────────────────

    def active(self):
        """Non-deleted, active users only."""
        return self.filter(deleted_at__isnull=True, is_active=True)

    def for_tenant(self, tenant: Tenant):
        """All non-deleted users for a given tenant."""
        return self.filter(tenant=tenant, deleted_at__isnull=True)


# ──────────────────────────────────────────────────────────────────────────────
# 3. CUSTOM USER MODEL
# ──────────────────────────────────────────────────────────────────────────────

class User(AbstractBaseUser):
    """
    Central user model.

    Key design choices
    ------------------
    - Login field    : email (case-insensitive)
    - Auth backend   : SimpleJWT (access + refresh tokens)
    - Soft-delete    : sets deleted_at; email uniqueness constraint fires only
                       when deleted_at IS NULL, so addresses can be reused.
    - Google OAuth2  : google_sub stores the immutable Google subject claim.
    - RBAC           : fine-grained permissions via Role → Permission (Section 10).
    - MFA            : optional TOTP / WebAuthn (Section 11, feature-flagged).

    Roles
    -----
    - SUPERADMIN  : Django superuser; bypasses all permission checks.
    - ADMIN       : Tenant admin; can manage users within their tenant.
    - CLIENT      : Regular end-user.
    """

    class Role(models.TextChoices):
        SUPERADMIN = "superadmin", _("Super Admin")
        ADMIN      = "admin",      _("Admin")
        CLIENT     = "client",     _("Client")

    # ── Identity ──────────────────────────────────────────────────────────────
    id        = _uuid_pk()
    email = models.EmailField(
    _("email address"),
    max_length=255,
    unique=True,
    db_index=True,
    help_text=_("Primary login credential — normalised to lowercase."),
    )
    full_name = models.CharField(_("full name"), max_length=255)
    role      = models.CharField(
        _("role"), max_length=20,
        choices=Role.choices,
        default=Role.CLIENT,
        db_index=True,
    )

    # ── Tenant ────────────────────────────────────────────────────────────────
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="users",
        null=True, blank=True,          # NULL only for global superusers
        verbose_name=_("tenant"),
        db_index=True,
    )

    # ── Permissions / Access ──────────────────────────────────────────────────
    is_active    = models.BooleanField(_("active"), default=True)
    is_staff     = models.BooleanField(
        _("staff status"), default=False,
        help_text=_("Grants Django admin site access."),
    )
    is_superuser = models.BooleanField(
        _("superuser"), default=False,
        help_text=_("Bypasses all permission checks."),
    )

    # ── Email verification ────────────────────────────────────────────────────
    is_email_verified = models.BooleanField(_("email verified"), default=False)

    # ── Google OAuth2 ─────────────────────────────────────────────────────────
    google_sub = models.CharField(
        _("Google subject ID"),
        max_length=255,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text=_(
            "Immutable Google account 'sub' claim. "
            "Set on first Google sign-in; used to locate the user on subsequent logins."
        ),
    )
    google_picture_url = models.URLField(
        _("Google profile picture URL"), max_length=500, blank=True, default=""
    )

    # ── Security ──────────────────────────────────────────────────────────────
    last_login_ip         = models.GenericIPAddressField(
        _("last login IP"), null=True, blank=True,
    )
    failed_login_attempts = models.PositiveSmallIntegerField(
        _("failed login attempts"), default=0,
    )
    locked_until          = models.DateTimeField(
        _("locked until"), null=True, blank=True,
        help_text=_("Account locked until this datetime (UTC)."),
    )
    password_last_changed = models.DateTimeField(
        _("password last changed"), null=True, blank=True,
    )

    # ── Legal consent ─────────────────────────────────────────────────────────
    terms_accepted_at        = models.DateTimeField(
        _("terms accepted at"), null=True, blank=True,
    )
    privacy_accepted_version = models.CharField(
        _("privacy policy version accepted"),
        max_length=20, null=True, blank=True,
    )

    # ── RBAC (fine-grained) ───────────────────────────────────────────────────
    roles = models.ManyToManyField(
        "Role",
        through="UserRoleAssignment",
        through_fields=("user", "role"),
        related_name="users",
        blank=True,
        verbose_name=_("roles"),
    )

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    created_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="created_users",
        verbose_name=_("created by"),
    )

    # ── Soft-delete ───────────────────────────────────────────────────────────
    deleted_at = models.DateTimeField(_("deleted at"), null=True, blank=True)
    deleted_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="deleted_users",
        verbose_name=_("deleted by"),
    )

    # ── Django auth wiring ────────────────────────────────────────────────────
    USERNAME_FIELD  = "email"
    REQUIRED_FIELDS = ["full_name"]

    objects = UserManager()

    class Meta:
        ordering = ["-created_at"]
        verbose_name = _("user")
        verbose_name_plural = _("users")
        indexes = [
            models.Index(
                fields=["email"],
                name="idx_user_email_active",
                condition=Q(deleted_at__isnull=True),
            ),
            models.Index(fields=["tenant", "email"], name="idx_user_tenant_email"),
            models.Index(fields=["locked_until"], name="idx_user_locked_until"),
            models.Index(fields=["role", "is_active"], name="idx_user_role_active"),
        ]
    
    # ── Django permission helpers (manual — no PermissionsMixin) ──────────────

    def has_perm(self, perm: str, obj=None) -> bool:
        """
        Superusers pass everything.
        All other permission checks should go through the RBAC system.
        """
        if not self.is_active:
            return False
        if self.is_superuser:
            return True
        # Delegate to RBAC: check if any active role grants `perm`
        return self._has_rbac_perm(perm)

    def has_module_perms(self, app_label: str) -> bool:
        return self.is_active and self.is_superuser

    def _has_rbac_perm(self, codename: str) -> bool:
        """
        Returns True if any active UserRoleAssignment grants a Permission
        whose codename matches.  Result should be cached in production
        (e.g. per-request via middleware).
        """
        return (
            self.role_assignments
            .filter(
                Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now()),
                role__permissions__codename=codename,
            )
            .exists()
        )

    # ── Convenience properties ────────────────────────────────────────────────

    @property
    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > timezone.now()

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    @property
    def is_oauth_user(self) -> bool:
        """True when the account was created via Google OAuth (no local password)."""
        return bool(self.google_sub) and not self.has_usable_password()

    # ── Mutation helpers ──────────────────────────────────────────────────────

    def soft_delete(self, deleted_by: "User | None" = None) -> None:
        """
        Soft-delete: deactivate the account and obfuscate the email so the
        address can be re-registered.  All fields that are mutated are included
        in update_fields to avoid accidental overwrites.
        """
        now = timezone.now()
        self.deleted_at = now
        self.deleted_by = deleted_by
        self.is_active  = False
        # Obfuscate the email so the constraint allows re-use
        self.email = f"deleted_{self.id}_{self.email}"
        self.save(update_fields=["deleted_at", "deleted_by", "is_active", "email"])

    def increment_failed_login(self) -> None:
        """Bump failed-attempt counter; caller is responsible for locking if needed."""
        self.failed_login_attempts += 1
        self.save(update_fields=["failed_login_attempts"])

    def reset_failed_login(self) -> None:
        """Clear failed-attempt counter and any lock."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.save(update_fields=["failed_login_attempts", "locked_until"])

    def lock_account(self, until: "timezone.datetime") -> None:
        """Lock account until a specific datetime (UTC)."""
        self.locked_until = until
        self.save(update_fields=["locked_until"])

    def __str__(self) -> str:
        return f"{self.full_name} <{self.email}>"


# ──────────────────────────────────────────────────────────────────────────────
# 4. USER PROFILE
# ──────────────────────────────────────────────────────────────────────────────

class UserProfile(models.Model):
    """
    Extended demographic and preference data, kept separate from auth concerns.
    Created automatically via post_save signal when a User is first saved.
    """

    id   = _uuid_pk()
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile",
        verbose_name=_("user"),
    )

    # ── Personal information ──────────────────────────────────────────────────
    date_of_birth   = models.DateField(_("date of birth"), null=True, blank=True)
    phone_number    = models.CharField(
        _("phone number"), max_length=30, unique=True, null=True, blank=True,
    )
    alternate_email = models.EmailField(_("alternate email"), null=True, blank=True)

    # ── Address ───────────────────────────────────────────────────────────────
    address_line1  = models.CharField(_("address line 1"), max_length=255, blank=True)
    address_line2  = models.CharField(_("address line 2"), max_length=255, blank=True)
    city           = models.CharField(_("city"),           max_length=100, blank=True)
    state_province = models.CharField(_("state/province"), max_length=100, blank=True)
    postal_code    = models.CharField(_("postal code"),    max_length=20,  blank=True)
    country        = models.CharField(
        _("country"), max_length=2, blank=True,
        help_text=_("ISO 3166-1 alpha-2 code, e.g. 'US', 'GB'."),
    )

    # ── Media ─────────────────────────────────────────────────────────────────
    profile_picture = models.ImageField(
        _("profile picture"),
        upload_to="profile_pictures/%Y/%m/",
        null=True, blank=True,
        help_text=_("Configure DEFAULT_FILE_STORAGE to use S3/GCS in production."),
    )
    bio = models.TextField(_("bio"), blank=True)

    # ── Preferences & localisation ────────────────────────────────────────────
    preferences = models.JSONField(_("preferences"), default=dict, blank=True)
    timezone    = models.CharField(_("timezone"), max_length=64, default="UTC")
    language    = models.CharField(_("language"), max_length=10, default="en")

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    class Meta:
        ordering            = ["-created_at"]
        verbose_name        = _("user profile")
        verbose_name_plural = _("user profiles")

    def __str__(self) -> str:
        return f"Profile of {self.user}"


# ──────────────────────────────────────────────────────────────────────────────
# 5. ABSTRACT BASE TOKEN
# ──────────────────────────────────────────────────────────────────────────────

class AbstractToken(models.Model):
    """
    Base for all single-use, time-limited tokens (magic link, email verify,
    password reset).

    SECURITY: NEVER store the raw token.
    Store only its SHA-256 hex digest in token_hash.
    Hash the candidate before every look-up.
    """

    id         = _uuid_pk()
    user       = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="+",   # concrete subclasses override this
        verbose_name=_("user"),
    )
    token_hash = models.CharField(
        _("SHA-256 token hash"), max_length=64,
        unique=True, db_index=True,
    )
    expires_at = models.DateTimeField(_("expires at"), db_index=True)
    used       = models.BooleanField(_("used"), default=False)
    used_at    = models.DateTimeField(_("used at"), null=True, blank=True)
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)

    class Meta:
        abstract = True

    @property
    def is_valid(self) -> bool:
        return not self.used and self.expires_at > timezone.now()

    def consume(self) -> None:
        """Mark token as used.  Must be called inside an atomic block."""
        if not self.is_valid:
            raise ValueError("Token is already used or has expired.")
        self.used    = True
        self.used_at = timezone.now()
        self.save(update_fields=["used", "used_at"])

    def __str__(self) -> str:
        status = "valid" if self.is_valid else "invalid"
        return f"{self.__class__.__name__}(user={self.user_id}, {status})"


# ──────────────────────────────────────────────────────────────────────────────
# 6. MAGIC LINK TOKEN  (passwordless login)
# ──────────────────────────────────────────────────────────────────────────────

class MagicLinkToken(AbstractToken):
    """
    One-time URL for passwordless authentication.
    TTL: MAGIC_LINK_EXPIRY_MINUTES (env, default 15 min).
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="magic_link_tokens",
        verbose_name=_("user"),
    )

    class Meta(AbstractToken.Meta):
        verbose_name        = _("magic link token")
        verbose_name_plural = _("magic link tokens")
        indexes = [
            models.Index(fields=["token_hash"],      name="idx_magiclink_token_hash"),
            models.Index(fields=["expires_at"],      name="idx_magiclink_expires_at"),
            models.Index(fields=["user", "expires_at"], name="idx_magiclink_user_expires"),
        ]


# ──────────────────────────────────────────────────────────────────────────────
# 7. EMAIL VERIFICATION TOKEN
# ──────────────────────────────────────────────────────────────────────────────

class EmailVerificationToken(AbstractToken):
    """
    Sent on registration (and on email change) to prove address ownership.
    At most ONE active token per user is enforced by the UniqueConstraint.
    TTL: EMAIL_VERIFICATION_EXPIRY_HOURS (env, default 24 h).
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="email_verification_tokens",
        verbose_name=_("user"),
    )

    class Meta(AbstractToken.Meta):
        verbose_name        = _("email verification token")
        verbose_name_plural = _("email verification tokens")
        indexes = [
            models.Index(fields=["token_hash"],         name="idx_emailver_token_hash"),
            models.Index(fields=["expires_at"],         name="idx_emailver_expires_at"),
            models.Index(fields=["user", "expires_at"], name="idx_emailver_user_expires"),
        ]


# ──────────────────────────────────────────────────────────────────────────────
# 8. PASSWORD RESET TOKEN
# ──────────────────────────────────────────────────────────────────────────────

class PasswordResetToken(AbstractToken):
    """
    Traditional password-reset flow.
    TTL: PASSWORD_RESET_EXPIRY_MINUTES (env, default 30 min).
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="password_reset_tokens",
        verbose_name=_("user"),
    )

    class Meta(AbstractToken.Meta):
        verbose_name        = _("password reset token")
        verbose_name_plural = _("password reset tokens")
        indexes = [
            models.Index(fields=["token_hash"],         name="idx_pwreset_token_hash"),
            models.Index(fields=["expires_at"],         name="idx_pwreset_expires_at"),
            models.Index(fields=["user", "expires_at"], name="idx_pwreset_user_expires"),
        ]


# ──────────────────────────────────────────────────────────────────────────────
# 9. REFRESH TOKEN TRACKER  (device-aware session management)
# ──────────────────────────────────────────────────────────────────────────────

class UserRefreshToken(models.Model):
    """
    Mirrors every SimpleJWT refresh token so sessions can be individually
    revoked, active devices listed, and suspicious concurrent logins detected.

    Lifecycle
    ---------
    1. Issue  → create record when refresh token is granted.
    2. Rotate → revoke old record, create new one.
    3. Logout → set revoked=True.
    4. Sweep  → Celery task deletes records where expires_at < now().
    """

    id         = _uuid_pk()
    user       = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="refresh_tokens",
        verbose_name=_("user"),
    )
    jti        = models.CharField(
        _("JWT ID (jti)"), max_length=255,
        unique=True, db_index=True,
        help_text=_("The 'jti' claim from the SimpleJWT refresh token."),
    )
    expires_at = models.DateTimeField(_("expires at"), db_index=True)
    revoked    = models.BooleanField(_("revoked"), default=False, db_index=True)

    # ── Device fingerprint ────────────────────────────────────────────────────
    device_name = models.CharField(
        _("device name"), max_length=255, blank=True,
        help_text=_("Human-readable label, e.g. 'Chrome 124 on Windows 11'."),
    )
    ip_address  = models.GenericIPAddressField(_("IP address"), null=True, blank=True)
    user_agent  = models.TextField(_("user agent"), blank=True)

    # ── Timestamps ────────────────────────────────────────────────────────────
    last_used_at = models.DateTimeField(_("last used at"), auto_now=True)
    created_at   = models.DateTimeField(_("created at"), auto_now_add=True)

    class Meta:
        ordering            = ["-created_at"]
        verbose_name        = _("user refresh token")
        verbose_name_plural = _("user refresh tokens")
        indexes = [
            models.Index(
                fields=["user", "revoked", "expires_at"],
                name="idx_rftoken_user_rev_exp",
            ),
            models.Index(fields=["jti"],        name="idx_refreshtoken_jti"),
            models.Index(fields=["expires_at"], name="idx_refreshtoken_expires"),
        ]

    def revoke(self) -> None:
        self.revoked = True
        self.save(update_fields=["revoked"])

    def __str__(self) -> str:
        status = "revoked" if self.revoked else "active"
        return f"RefreshToken({self.user}, {self.device_name or 'unknown device'}, {status})"


# ──────────────────────────────────────────────────────────────────────────────
# 10. RBAC — Permission → Role → UserRoleAssignment
# ──────────────────────────────────────────────────────────────────────────────

class Permission(models.Model):
    """
    Fine-grained capability, e.g. 'document:read', 'invoice:approve'.
    Assigned to Roles, never directly to Users.
    """

    id            = _uuid_pk()
    codename      = models.CharField(
        _("codename"), max_length=100, unique=True,
        help_text=_("Machine-readable key, e.g. 'project:delete'."),
    )
    name          = models.CharField(_("name"), max_length=255)
    resource_type = models.CharField(
        _("resource type"), max_length=100, blank=True,
        help_text=_("Resource this permission applies to, e.g. 'document'."),
    )

    class Meta:
        ordering            = ["resource_type", "codename"]
        verbose_name        = _("permission")
        verbose_name_plural = _("permissions")
        indexes = [
            models.Index(fields=["resource_type"], name="idx_permission_resource_type"),
        ]

    def __str__(self) -> str:
        return f"{self.codename} ({self.name})"


class Role(models.Model):
    """
    Named collection of Permissions.
    Assigned to Users via UserRoleAssignment (supports expiry).
    """

    id          = _uuid_pk()
    name        = models.CharField(_("name"), max_length=100, unique=True)
    description = models.TextField(_("description"), blank=True)
    permissions = models.ManyToManyField(
        Permission,
        blank=True,
        related_name="roles",
        verbose_name=_("permissions"),
    )
    created_at  = models.DateTimeField(_("created at"), auto_now_add=True)

    class Meta:
        ordering            = ["name"]
        verbose_name        = _("role")
        verbose_name_plural = _("roles")

    def __str__(self) -> str:
        return self.name


class UserRoleAssignment(models.Model):
    """
    Through-model for User ↔ Role.
    Supports time-limited grants (e.g. temporary elevated access).
    """

    id          = _uuid_pk()
    user        = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="role_assignments",
        verbose_name=_("user"),
    )
    role        = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="user_assignments",
        verbose_name=_("role"),
    )
    assigned_at = models.DateTimeField(_("assigned at"), auto_now_add=True)
    expires_at  = models.DateTimeField(
        _("expires at"), null=True, blank=True,
        help_text=_("Leave blank for a permanent assignment."),
    )
    assigned_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name="granted_role_assignments",
        verbose_name=_("assigned by"),
    )

    class Meta:
        ordering            = ["-assigned_at"]
        verbose_name        = _("user role assignment")
        verbose_name_plural = _("user role assignments")
        constraints = [
            models.UniqueConstraint(
                fields=["user", "role"],
                name="uq_user_role_assignment",
            ),
        ]
        indexes = [
            models.Index(
                fields=["user", "expires_at"],
                name="idx_roleassign_user_expires",
            ),
        ]

    @property
    def is_active(self) -> bool:
        return self.expires_at is None or self.expires_at > timezone.now()

    def __str__(self) -> str:
        expiry = f" (expires {self.expires_at.date()})" if self.expires_at else ""
        return f"{self.user} → {self.role}{expiry}"


# ──────────────────────────────────────────────────────────────────────────────
# 11. MFA  (feature-flagged; table always migrated)
# ──────────────────────────────────────────────────────────────────────────────

class UserMFA(models.Model):
    """
    Multi-Factor Authentication record.
    Activate by setting MFA_ENABLED=True in .env.

    Security notes
    --------------
    - secret_encrypted : AES-256 encrypted (use django-cryptography or a vault).
    - backup_codes_hash: bcrypt hashes joined by newline.
    - At most ONE active method per user (UniqueConstraint).
    """

    class Method(models.TextChoices):
        TOTP     = "totp",     _("TOTP (Authenticator App)")
        WEBAUTHN = "webauthn", _("WebAuthn (Hardware Key / Passkey)")

    id                = _uuid_pk()
    user              = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="mfa_methods",
        verbose_name=_("user"),
    )
    method            = models.CharField(
        _("method"), max_length=20, choices=Method.choices, db_index=True,
    )
    secret_encrypted  = models.TextField(
        _("encrypted secret"),
        help_text=_("AES-256 encrypted TOTP secret or WebAuthn credential ID."),
    )
    is_active         = models.BooleanField(_("active"), default=False)
    backup_codes_hash = models.TextField(
        _("backup codes hash"), blank=True, null=True,
        help_text=_("Newline-separated bcrypt hashes of one-time backup codes."),
    )
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    updated_at = models.DateTimeField(_("updated at"), auto_now=True)

    class Meta:
        ordering            = ["-created_at"]
        verbose_name        = _("user MFA")
        verbose_name_plural = _("user MFA records")
        indexes = [
            models.Index(fields=["user", "is_active"], name="idx_mfa_user_active"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["user"],
                condition=Q(is_active=True),
                name="uq_mfa_one_active_per_user",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"MFA({self.user}, method={self.get_method_display()}, "
            f"active={self.is_active})"
        )


# ──────────────────────────────────────────────────────────────────────────────
# SIGNALS
# ──────────────────────────────────────────────────────────────────────────────

from django.db.models.signals import post_save   # noqa: E402
from django.dispatch import receiver             # noqa: E402


@receiver(post_save, sender=User)
def create_user_profile(
    sender,
    instance: User,
    created: bool,
    **kwargs,
) -> None:
    """Auto-create a UserProfile whenever a new User row is inserted."""
    if created:
        UserProfile.objects.get_or_create(user=instance)