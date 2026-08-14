from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import Mock, patch

import pytest
from ldap3.core.exceptions import LDAPException
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.ldap_auth import (
    LDAPAccessDenied,
    LDAPClient,
    LDAPConfigurationError,
    LDAPIdentity,
    LDAPUnavailable,
)
from portal.models import AuditEvent, User, db
from portal.pve import FakePVEClient


@dataclass
class FakeLDAPClient:
    result: LDAPIdentity | None = None
    error: Exception | None = None
    calls: int = 0

    def authenticate(self, username, password):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result

    def check_connection(self):
        if self.error is not None:
            raise self.error


def make_app(ldap_client):
    return create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("admin-password"),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=FakePVEClient(accessible_isos={"pve-a": set()}),
        ldap_client=ldap_client,
    )


def configured_app_values(**overrides):
    values = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "PORTAL_ADMIN_USERNAME": "admin",
        "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("admin-password"),
        "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        "PORTAL_LDAP_URI": "ldaps://ad.chu.fr",
        "PORTAL_LDAP_BIND_DN": "CN=svc,DC=chu,DC=fr",
        "PORTAL_LDAP_BIND_PASSWORD": "bind-secret",
        "PORTAL_LDAP_BASE_DN": "DC=chu,DC=fr",
        "PORTAL_LDAP_GROUP_USER": "CN=Portal-Users,DC=chu,DC=fr",
    }
    values.update(overrides)
    return values


def test_ldap_login_provisions_user_and_synchronizes_role():
    ldap = FakeLDAPClient(
        LDAPIdentity(
            "ldaps://ad.chu.fr",
            "CN=Alice,OU=Users,DC=chu,DC=fr",
            "alice",
            "user",
        )
    )
    app = make_app(ldap)
    client = app.test_client()

    response = client.post("/login", json={"username": "alice", "password": "secret"})

    assert response.status_code == 200
    assert response.get_json()["user"]["authentication"] == "ldap"
    with app.app_context():
        user = db.session.scalar(select(User).where(User.username == "alice"))
        assert user.password_hash is None
        assert user.external_subject.startswith("CN=Alice")
        ldap.result = LDAPIdentity(
            "ldaps://ad.chu.fr", user.external_subject, "alice", "operator"
        )
    client.post("/logout", headers={"X-CSRF-Token": response.get_json()["csrf_token"]})
    second = client.post("/login", json={"username": "alice", "password": "secret"})
    assert second.get_json()["user"]["role"] == "operator"


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (LDAPAccessDenied("group"), 403, "ldap_access_denied"),
        (LDAPUnavailable("offline"), 503, "ldap_unavailable"),
    ],
)
def test_ldap_failures_are_generic_and_audited(error, status, code):
    app = make_app(FakeLDAPClient(error=error))
    response = app.test_client().post(
        "/login", json={"username": "alice", "password": "secret"}
    )
    assert response.status_code == status
    assert response.get_json()["error"] == code
    with app.app_context():
        assert db.session.scalar(
            select(AuditEvent).where(AuditEvent.action == "authentication.ldap_login")
        ) is not None


def test_invalid_ldap_password_and_local_collision_are_not_confused():
    ldap = FakeLDAPClient(result=None)
    app = make_app(ldap)
    client = app.test_client()
    assert client.post(
        "/login", json={"username": "alice", "password": "wrong"}
    ).status_code == 401
    calls = ldap.calls
    assert client.post(
        "/login", json={"username": "admin", "password": "wrong"}
    ).status_code == 401
    assert ldap.calls == calls


def test_ldap_cli_check_uses_configured_client():
    app = make_app(FakeLDAPClient())
    result = app.test_cli_runner().invoke(args=["check-ldap"])
    assert result.exit_code == 0
    assert "validés" in result.output


def test_application_builds_native_ldap_client_from_configuration():
    ldap = FakeLDAPClient()
    with patch("portal.LDAPClient", return_value=ldap) as constructor:
        app = create_app(
            configured_app_values(),
            pve_client=FakePVEClient(accessible_isos={"pve-a": set()}),
        )
    assert app.config["PORTAL_LDAP_ENABLED"] is True
    assert constructor.call_args.kwargs["uri"] == "ldaps://ad.chu.fr"
    assert constructor.call_args.kwargs["role_groups"]["user"].startswith("CN=")


def test_application_rejects_invalid_ldap_configuration_and_quota():
    with pytest.raises(ValueError, match="Configuration LDAP invalide"):
        create_app(
            configured_app_values(PORTAL_LDAP_GROUP_USER=""),
            pve_client=FakePVEClient(accessible_isos={"pve-a": set()}),
        )
    with patch("portal.LDAPClient", return_value=FakeLDAPClient()):
        with pytest.raises(ValueError, match="PORTAL_LDAP_DEFAULT_QUOTA_VMS"):
            create_app(
                configured_app_values(PORTAL_LDAP_DEFAULT_QUOTA_VMS=101),
                pve_client=FakePVEClient(accessible_isos={"pve-a": set()}),
            )


def ldap_config(**overrides):
    values = {
        "uri": "ldaps://ad.chu.fr",
        "base_dn": "DC=chu,DC=fr",
        "user_filter": "(sAMAccountName={username})",
        "username_attribute": "sAMAccountName",
        "group_attribute": "memberOf",
        "role_groups": {"user": "CN=Portal-Users,DC=chu,DC=fr"},
        "bind_dn": "CN=svc,DC=chu,DC=fr",
        "bind_password": "bind-secret",
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    "override",
    [
        {"uri": "http://ad.chu.fr"},
        {"uri": "ldap://ad.chu.fr", "start_tls": False},
        {"user_filter": "(uid=alice)"},
        {"bind_password": ""},
        {"base_dn": ""},
        {"role_groups": {}},
    ],
)
def test_ldap_configuration_rejects_unsafe_values(override):
    with pytest.raises(LDAPConfigurationError):
        LDAPClient(**ldap_config(**override))


class Attribute:
    def __init__(self, values):
        self.values = values


class Entry:
    entry_dn = "CN=Alice,OU=Users,DC=chu,DC=fr"

    def __init__(self, username=("alice",), groups=("CN=Portal-Users,DC=chu,DC=fr",)):
        self.attributes = {
            "sAMAccountName": Attribute(list(username)),
            "memberOf": Attribute(list(groups)),
        }

    def __getitem__(self, key):
        return self.attributes[key]


def connection(*, open_result=True, tls_result=True, bind_result=True, search_result=True, entries=None):
    value = Mock()
    value.open.return_value = open_result
    value.start_tls.return_value = tls_result
    value.bind.return_value = bind_result
    value.search.return_value = search_result
    value.entries = [Entry()] if entries is None else entries
    return value


def test_ldap_client_searches_safely_binds_user_and_maps_role():
    service = connection(entries=[Entry(groups=("CN=Portal-Admins,DC=chu,DC=fr",))])
    user = connection()
    with patch("portal.ldap_auth.Connection", side_effect=[service, user]):
        client = LDAPClient(
            **ldap_config(
                role_groups={
                    "admin": "CN=Portal-Admins,DC=chu,DC=fr",
                    "user": "CN=Portal-Users,DC=chu,DC=fr",
                }
            )
        )
        identity = client.authenticate("ali*)(ce", "secret")
    assert identity is not None
    assert identity.role == "admin"
    assert identity.username == "alice"
    assert "\\2a" in service.search.call_args.args[1]
    assert service.unbind.called and user.unbind.called


def test_ldap_client_handles_transport_search_credentials_and_groups():
    client = LDAPClient(**ldap_config(uri="ldap://ad.chu.fr"))
    with patch("portal.ldap_auth.Connection", return_value=connection(open_result=False)):
        with pytest.raises(LDAPUnavailable):
            client.check_connection()
    with patch("portal.ldap_auth.Connection", return_value=connection(tls_result=False)):
        with pytest.raises(LDAPUnavailable):
            client.check_connection()
    with patch("portal.ldap_auth.Connection", return_value=connection(bind_result=False)):
        with pytest.raises(LDAPUnavailable):
            client.check_connection()
    with patch(
        "portal.ldap_auth.Connection",
        side_effect=[connection(search_result=False), connection()],
    ):
        assert client.authenticate("alice", "secret") is None
    with patch(
        "portal.ldap_auth.Connection",
        side_effect=[connection(entries=[Entry(), Entry()]), connection()],
    ):
        assert client.authenticate("alice", "secret") is None
    with patch(
        "portal.ldap_auth.Connection",
        side_effect=[connection(), connection(bind_result=False)],
    ):
        assert client.authenticate("alice", "secret") is None
    with patch(
        "portal.ldap_auth.Connection",
        side_effect=[connection(entries=[Entry(groups=("other",))]), connection()],
    ):
        with pytest.raises(LDAPAccessDenied):
            client.authenticate("alice", "secret")


@pytest.mark.parametrize(
    ("username", "password"),
    [("", "secret"), ("alice", ""), ("a" * 129, "secret"), ("alice", "x" * 1025)],
)
def test_ldap_client_rejects_invalid_credential_shapes(username, password):
    client = LDAPClient(**ldap_config())
    assert client.authenticate(username, password) is None


def test_ldap_client_handles_bind_and_directory_exceptions():
    client = LDAPClient(**ldap_config())
    with patch("portal.ldap_auth.Connection", return_value=connection(bind_result=False)):
        with pytest.raises(LDAPUnavailable, match="Bind de service"):
            client.authenticate("alice", "secret")

    service = connection()
    service.search.side_effect = LDAPException("directory failure")
    with patch("portal.ldap_auth.Connection", return_value=service):
        with pytest.raises(LDAPUnavailable, match="Recherche"):
            client.authenticate("alice", "secret")

    invalid_name = connection(entries=[Entry(username=("alice", "alias"))])
    with patch("portal.ldap_auth.Connection", return_value=invalid_name):
        assert client.authenticate("alice", "secret") is None

    malformed_identity = connection(entries=[Entry(username=("alice invalid",))])
    with patch("portal.ldap_auth.Connection", return_value=malformed_identity):
        with pytest.raises(LDAPAccessDenied, match="Identité"):
            client.authenticate("alice", "secret")

    user = connection()
    user.bind.side_effect = LDAPException("bind failure")
    with patch("portal.ldap_auth.Connection", side_effect=[connection(), user]):
        assert client.authenticate("alice", "secret") is None
