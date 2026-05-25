# ==============================================================================
# config/celery.py
# ==============================================================================
"""
Celery application entry point.

In config/__init__.py, add:
    from .celery import app as celery_app
    __all__ = ("celery_app",)
"""

import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("config")

# Read Celery config from settings with the CELERY_ namespace prefix.
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-discover tasks from all INSTALLED_APPS (looks for tasks.py in each app).
app.autodiscover_tasks()


# ==============================================================================
# config/urls.py  (root URL configuration)
# ==============================================================================
"""
from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    # Django Admin  (internal staff only — never expose to the public internet)
    path("admin/", admin.site.urls),

    # Client-facing API v1
    path("api/v1/", include("apps.accounts.api.urls", namespace="accounts")),

    # OpenAPI schema + Swagger UI (restrict or disable in production)
    path("api/schema/",      SpectacularAPIView.as_view(), name="schema"),
    path("api/schema/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
]
"""


# ==============================================================================
# apps/accounts/apps.py
# ==============================================================================
"""
from django.apps import AppConfig


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name               = "apps.accounts"
    verbose_name       = "Accounts"

    def ready(self) -> None:
        # Import models to ensure the post_save signal (auto-create UserProfile)
        # is registered when Django starts.
        import apps.accounts.models  # noqa: F401
"""


# ==============================================================================
# .env.example
# ==============================================================================
"""
# ── Django Core ──────────────────────────────────────────────────────────────
SECRET_KEY=replace-with-a-long-random-string-at-least-50-chars
DEBUG=False
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# ── Database (PostgreSQL) ─────────────────────────────────────────────────────
DB_NAME=saas_db
DB_USER=saas_user
DB_PASSWORD=saas_password
DB_HOST=localhost
DB_PORT=5432

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379/2
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1

# ── Email (Gmail SMTP) ────────────────────────────────────────────────────────
# Use a Gmail App Password — NOT your regular password.
# Enable at: https://myaccount.google.com/apppasswords
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-app@gmail.com
EMAIL_HOST_PASSWORD=your-gmail-app-password
DEFAULT_FROM_EMAIL=SaaS App <your-app@gmail.com>

# ── SimpleJWT ─────────────────────────────────────────────────────────────────
# Use a separate signing key — NOT the Django SECRET_KEY.
JWT_SIGNING_KEY=replace-with-a-long-random-jwt-signing-key
JWT_ACCESS_TOKEN_LIFETIME_MINUTES=15
JWT_REFRESH_TOKEN_LIFETIME_DAYS=7

# ── Token TTLs ────────────────────────────────────────────────────────────────
MAGIC_LINK_EXPIRY_MINUTES=15
EMAIL_VERIFICATION_EXPIRY_HOURS=24
PASSWORD_RESET_EXPIRY_MINUTES=30

# ── Application ───────────────────────────────────────────────────────────────
FRONTEND_BASE_URL=https://app.yourdomain.com
APP_NAME=SaaS App
MFA_ENABLED=False
"""


# ==============================================================================
# COMPLETE CURL TESTING GUIDE
# ==============================================================================
"""
BASE=http://localhost:8000/api/v1

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HAPPY PATH — full flow from registration to logout
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

── STEP 1: Register ─────────────────────────────────────────────────────────

curl -s -X POST "$BASE/auth/register/" \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com", "full_name": "Alice Example"}'

Expected → 201:
{
  "detail": "Account created. Please check your email for a sign-in link ..."
}

Error (duplicate email) → 400:
{
  "email": ["A user with this email already exists."]
}

── STEP 2: Click the link / verify the magic link ───────────────────────────
(In production the user clicks the link in their email.
 In dev, grab the raw_token from the Celery worker logs or from the DB.)

TOKEN="the-raw-token-from-the-email"

curl -s -X GET "$BASE/auth/magic/verify/?token=$TOKEN"

Expected → 200:
{
  "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "alice@example.com",
    "full_name": "Alice Example",
    "role": "client",
    "is_email_verified": true,
    "tenant": { "slug": "acme-corp", "name": "Acme Corp", "subscription_tier": "free" },
    "profile": { "timezone": "UTC", "language": "en", ... }
  }
}

Error (invalid/expired) → 401:
{ "detail": "Invalid or expired token." }

── STEP 3: Get current user ─────────────────────────────────────────────────

ACCESS="<access_token_from_step_2>"

curl -s -X GET "$BASE/users/me/" \
  -H "Authorization: Bearer $ACCESS"

Expected → 200: same user object as above.

── STEP 4: Update profile ───────────────────────────────────────────────────

curl -s -X PATCH "$BASE/users/me/" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "Alice B. Example",
    "profile": {
      "bio": "Engineer. Coffee addict.",
      "timezone": "Europe/Amsterdam",
      "city": "Amsterdam",
      "country": "NL"
    }
  }'

Expected → 200: updated user object.

── STEP 5: Request another magic link (subsequent logins) ───────────────────

curl -s -X POST "$BASE/auth/magic/request/" \
  -H "Content-Type: application/json" \
  -d '{"email": "alice@example.com"}'

Expected → 200 (always — anti-enumeration):
{ "detail": "If an account exists, a link has been sent." }

── STEP 6: Refresh the access token ─────────────────────────────────────────

REFRESH="<refresh_token_from_step_2>"

curl -s -X POST "$BASE/auth/token/refresh/" \
  -H "Content-Type: application/json" \
  -d "{\"refresh\": \"$REFRESH\"}"

Expected → 200: { "access": "...", "refresh": "...", "user": {...} }
(The old refresh token is now revoked; use the NEW refresh token from here on.)

── STEP 7: Set a password (first time — no current_password needed) ─────────

curl -s -X POST "$BASE/auth/change-password/" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d '{
    "new_password": "Sup3rS3cure!",
    "confirm_password": "Sup3rS3cure!"
  }'

Expected → 200:
{ "detail": "Password updated successfully." }

── STEP 8: Logout (current device) ──────────────────────────────────────────

curl -s -X POST "$BASE/auth/logout/" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"refresh\": \"$REFRESH\"}"

Expected → 200:
{ "detail": "Successfully logged out." }

── STEP 9: Logout all devices ───────────────────────────────────────────────

curl -s -X POST "$BASE/auth/logout/" \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json" \
  -d "{\"refresh\": \"$REFRESH\", \"all_devices\": true}"

── STEP 10: Attempt to reuse the revoked refresh token ──────────────────────

curl -s -X POST "$BASE/auth/token/refresh/" \
  -H "Content-Type: application/json" \
  -d "{\"refresh\": \"$REFRESH\"}"

Expected → 401:
{ "detail": "Token has been revoked. Please log in again." }

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DEV TIPS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. To skip actual email delivery in development, set in .env:
     EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
   The raw token will be printed to the Celery worker stdout.

2. To inspect the DB directly after registration:
     SELECT token_hash, expires_at, used FROM accounts_magiclinktoken ORDER BY created_at DESC LIMIT 5;

3. To run the cleanup task manually from a Django shell:
     from apps.accounts.tasks import cleanup_expired_tokens
     cleanup_expired_tokens.apply()

4. Swagger UI available at:
     http://localhost:8000/api/schema/docs/
"""