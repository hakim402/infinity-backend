from __future__ import annotations

from types import SimpleNamespace

import pytest
from rest_framework.test import APIRequestFactory

from apps.accounts.permissions import (
    HasRBACPermission,
    IsAdminOrReadOnly,
    IsAdminUser,
    IsClientUser,
    IsClientUserOrReadOnly,
    IsEmailVerified,
    IsOwnerOrAdmin,
    IsSameTenant,
    IsSuperAdmin,
)
from apps.accounts.models import User
from .factories import assign_role_with_permission, create_tenant, create_user


pytestmark = pytest.mark.django_db


factory = APIRequestFactory()


def attach_user(request, user):
    request.user = user
    return request


def test_is_client_user_allows_only_live_client():
    user = create_user(role=User.Role.CLIENT)
    request = attach_user(factory.get("/"), user)

    assert IsClientUser().has_permission(request, SimpleNamespace()) is True

    user.role = User.Role.ADMIN
    user.save(update_fields=["role"])

    assert IsClientUser().has_permission(request, SimpleNamespace()) is False


def test_is_client_user_or_read_only_allows_authenticated_safe_method():
    admin = create_user(role=User.Role.ADMIN)
    get_request = attach_user(factory.get("/"), admin)
    post_request = attach_user(factory.post("/"), admin)

    assert IsClientUserOrReadOnly().has_permission(get_request, SimpleNamespace()) is True
    assert IsClientUserOrReadOnly().has_permission(post_request, SimpleNamespace()) is False


def test_is_admin_user_allows_admin_and_superadmin():
    admin = create_user(role=User.Role.ADMIN)
    superadmin = create_user(role=User.Role.SUPERADMIN, is_superuser=True)

    assert IsAdminUser().has_permission(attach_user(factory.get("/"), admin), SimpleNamespace()) is True
    assert IsAdminUser().has_permission(attach_user(factory.get("/"), superadmin), SimpleNamespace()) is True


def test_is_admin_or_read_only():
    client = create_user(role=User.Role.CLIENT)
    admin = create_user(role=User.Role.ADMIN)

    assert IsAdminOrReadOnly().has_permission(attach_user(factory.get("/"), client), SimpleNamespace()) is True
    assert IsAdminOrReadOnly().has_permission(attach_user(factory.post("/"), client), SimpleNamespace()) is False
    assert IsAdminOrReadOnly().has_permission(attach_user(factory.post("/"), admin), SimpleNamespace()) is True


def test_is_superadmin_allows_only_superadmin():
    user = create_user(role=User.Role.CLIENT)
    superadmin = create_user(role=User.Role.SUPERADMIN, is_superuser=True)

    assert IsSuperAdmin().has_permission(attach_user(factory.get("/"), user), SimpleNamespace()) is False
    assert IsSuperAdmin().has_permission(attach_user(factory.get("/"), superadmin), SimpleNamespace()) is True


def test_is_same_tenant_allows_same_tenant_and_blocks_other_tenant():
    tenant_a = create_tenant(slug="tenant-a")
    tenant_b = create_tenant(slug="tenant-b")
    user = create_user(tenant=tenant_a)
    same_obj = SimpleNamespace(tenant=tenant_a)
    other_obj = SimpleNamespace(tenant=tenant_b)

    request = attach_user(factory.get("/"), user)

    assert IsSameTenant().has_object_permission(request, SimpleNamespace(), same_obj) is True
    assert IsSameTenant().has_object_permission(request, SimpleNamespace(), other_obj) is False


def test_is_same_tenant_superadmin_bypass():
    tenant = create_tenant()
    superadmin = create_user(role=User.Role.SUPERADMIN, is_superuser=True)
    obj = SimpleNamespace(tenant=tenant)
    request = attach_user(factory.get("/"), superadmin)

    assert IsSameTenant().has_object_permission(request, SimpleNamespace(), obj) is True


def test_is_owner_or_admin():
    owner = create_user()
    other = create_user()
    admin = create_user(role=User.Role.ADMIN)
    obj = SimpleNamespace(user=owner)

    assert IsOwnerOrAdmin().has_object_permission(attach_user(factory.get("/"), owner), SimpleNamespace(), obj) is True
    assert IsOwnerOrAdmin().has_object_permission(attach_user(factory.get("/"), other), SimpleNamespace(), obj) is False
    assert IsOwnerOrAdmin().has_object_permission(attach_user(factory.get("/"), admin), SimpleNamespace(), obj) is True


def test_is_email_verified():
    user = create_user(is_email_verified=True)
    unverified = create_user(is_email_verified=False)

    assert IsEmailVerified().has_permission(attach_user(factory.get("/"), user), SimpleNamespace()) is True
    assert IsEmailVerified().has_permission(attach_user(factory.get("/"), unverified), SimpleNamespace()) is False


def test_has_rbac_permission():
    user = create_user()
    assign_role_with_permission(user, "invoice:approve")
    view = SimpleNamespace(required_permission="invoice:approve")

    assert HasRBACPermission().has_permission(attach_user(factory.get("/"), user), view) is True


def test_has_rbac_permission_allows_when_view_declares_no_required_permission():
    user = create_user()
    view = SimpleNamespace()

    assert HasRBACPermission().has_permission(attach_user(factory.get("/"), user), view) is True
