from __future__ import annotations

from unittest.mock import patch

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.models import User, UserRefreshToken
from .factories import (
    TEST_PASSWORD,
    create_email_verification_token,
    create_magic_link_token,
    create_password_reset_token,
    create_refresh_session,
    create_user,
)


pytestmark = pytest.mark.django_db


@pytest.fixture
def api_client():
    return APIClient()


@patch("apps.accounts.services.services._send_email")
def test_register_endpoint(mock_send_email, api_client, settings):
    settings.EMAIL_VERIFICATION_EXPIRY_HOURS = 24

    response = api_client.post(
        reverse("accounts:register"),
        {
            "email": "register@example.com",
            "full_name": "Register User",
            "password": TEST_PASSWORD,
            "password_confirm": TEST_PASSWORD,
            "terms_accepted": True,
        },
        format="json",
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.data["success"] is True
    assert User.objects.filter(email="register@example.com").exists()
    mock_send_email.assert_called_once()


def test_verify_email_endpoint(api_client):
    user = create_user(is_email_verified=False)
    _, raw_token = create_email_verification_token(user)

    response = api_client.post(
        reverse("accounts:verify-email"),
        {"token": raw_token},
        format="json",
    )

    user.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert response.data["success"] is True
    assert user.is_email_verified is True


def test_login_endpoint_returns_tokens(api_client):
    create_user(
        email="login-api@example.com",
        password=TEST_PASSWORD,
        is_email_verified=True,
    )

    response = api_client.post(
        reverse("accounts:login"),
        {"email": "login-api@example.com", "password": TEST_PASSWORD},
        format="json",
        HTTP_USER_AGENT="Mozilla/5.0 Chrome",
        REMOTE_ADDR="127.0.0.1",
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.data["success"] is True
    assert "access" in response.data
    assert "refresh" in response.data


def test_login_endpoint_rejects_bad_password(api_client):
    create_user(
        email="bad-login@example.com",
        password=TEST_PASSWORD,
        is_email_verified=True,
    )

    response = api_client.post(
        reverse("accounts:login"),
        {"email": "bad-login@example.com", "password": "WrongPass123!"},
        format="json",
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_logout_endpoint_revokes_session(api_client):
    user = create_user()
    session, refresh = create_refresh_session(user)
    api_client.force_authenticate(user=user)

    response = api_client.post(
        reverse("accounts:logout"),
        {"refresh": refresh},
        format="json",
    )

    session.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert session.revoked is True


def test_token_refresh_endpoint_rotates_refresh_token(api_client):
    user = create_user()
    session, refresh = create_refresh_session(user)

    response = api_client.post(
        reverse("accounts:token-refresh"),
        {"refresh": refresh},
        format="json",
        HTTP_USER_AGENT="Mozilla/5.0 Chrome",
        REMOTE_ADDR="127.0.0.1",
    )

    session.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert "access" in response.data
    assert "refresh" in response.data
    assert session.revoked is True


@patch("apps.accounts.services.services._send_email")
def test_magic_link_request_endpoint_always_returns_200(mock_send_email, api_client, settings):
    settings.MAGIC_LINK_EXPIRY_MINUTES = 15
    settings.FRONTEND_BASE_URL = "https://frontend.test"
    create_user(email="magic-api@example.com")

    response = api_client.post(
        reverse("accounts:magic-link-request"),
        {"email": "magic-api@example.com"},
        format="json",
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.data["success"] is True
    mock_send_email.assert_called_once()


def test_magic_link_verify_endpoint_returns_tokens(api_client):
    user = create_user(is_email_verified=False)
    _, raw_token = create_magic_link_token(user)

    response = api_client.post(
        reverse("accounts:magic-link-verify"),
        {"token": raw_token},
        format="json",
        HTTP_USER_AGENT="Mozilla/5.0 Chrome",
        REMOTE_ADDR="127.0.0.1",
    )

    user.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert "access" in response.data
    assert "refresh" in response.data
    assert user.is_email_verified is True


@patch("apps.accounts.services.services._send_email")
def test_password_reset_request_endpoint_always_returns_200(mock_send_email, api_client, settings):
    settings.PASSWORD_RESET_EXPIRY_MINUTES = 30
    settings.FRONTEND_BASE_URL = "https://frontend.test"
    create_user(email="reset-api@example.com")

    response = api_client.post(
        reverse("accounts:password-reset-request"),
        {"email": "reset-api@example.com"},
        format="json",
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.data["success"] is True
    mock_send_email.assert_called_once()


def test_password_reset_confirm_endpoint_changes_password(api_client):
    user = create_user(password=TEST_PASSWORD)
    _, raw_token = create_password_reset_token(user)

    response = api_client.post(
        reverse("accounts:password-reset-confirm"),
        {
            "token": raw_token,
            "password": "NewStrongPass123!",
            "password_confirm": "NewStrongPass123!",
        },
        format="json",
    )

    user.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert user.check_password("NewStrongPass123!")


def test_me_endpoint_requires_authentication(api_client):
    response = api_client.get(reverse("accounts:me"))

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_me_endpoint_returns_user_profile(api_client):
    user = create_user(email="me@example.com")
    api_client.force_authenticate(user=user)

    response = api_client.get(reverse("accounts:me"))

    assert response.status_code == status.HTTP_200_OK
    assert response.data["email"] == "me@example.com"
    assert "profile" in response.data


def test_update_me_endpoint_updates_user_and_profile(api_client):
    user = create_user()
    api_client.force_authenticate(user=user)

    response = api_client.patch(
        reverse("accounts:me-update"),
        {
            "full_name": "Updated API User",
            "profile": {"city": "Kabul", "country": "AF"},
        },
        format="json",
    )

    user.refresh_from_db()
    user.profile.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert user.full_name == "Updated API User"
    assert user.profile.city == "Kabul"


def test_change_password_endpoint(api_client):
    user = create_user(password=TEST_PASSWORD)
    api_client.force_authenticate(user=user)

    response = api_client.post(
        reverse("accounts:change-password"),
        {
            "current_password": TEST_PASSWORD,
            "new_password": "NewStrongPass123!",
            "new_password_confirm": "NewStrongPass123!",
        },
        format="json",
    )

    user.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert user.check_password("NewStrongPass123!")


def test_active_sessions_endpoint(api_client):
    user = create_user()
    create_refresh_session(user, device_name="Chrome Browser")
    api_client.force_authenticate(user=user)

    response = api_client.get(reverse("accounts:sessions"))

    assert response.status_code == status.HTTP_200_OK
    assert "sessions" in response.data
    assert len(response.data["sessions"]) == 1


def test_revoke_session_endpoint(api_client):
    user = create_user()
    session, _ = create_refresh_session(user)
    api_client.force_authenticate(user=user)

    response = api_client.delete(
        reverse("accounts:session-revoke", kwargs={"session_id": session.id})
    )

    session.refresh_from_db()

    assert response.status_code == status.HTTP_200_OK
    assert session.revoked is True


def test_revoke_session_endpoint_blocks_other_users_session(api_client):
    user = create_user()
    other = create_user()
    session, _ = create_refresh_session(other)
    api_client.force_authenticate(user=user)

    response = api_client.delete(
        reverse("accounts:session-revoke", kwargs={"session_id": session.id})
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
