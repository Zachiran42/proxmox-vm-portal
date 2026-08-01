from __future__ import annotations

import pytest
from authlib.integrations.base_client.errors import OAuthError
from flask import redirect
from requests import ConnectionError
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.models import AuditEvent, User, db
from portal.oidc import (
    OIDCIdentityError,
    collision_safe_username,
    extract_oidc_identity,
)
from portal.pve import FakePVEClient

ISSUER = "https://id.example.test/realms/portal"


class FakeOIDCClient:
    def __init__(self, claims=None, error=None, redirect_error=None):
        self.claims = claims or oidc_claims()
        self.error = error
        self.redirect_error = redirect_error
        self.redirect_calls = []

    def authorize_redirect(self, redirect_uri, **kwargs):
        if self.redirect_error:
            raise self.redirect_error
        self.redirect_calls.append((redirect_uri, kwargs))
        return redirect("https://id.example.test/authorize")

    def authorize_access_token(self):
        if self.error:
            raise self.error
        return {
            "access_token": "must-not-be-persisted",
            "id_token": "must-not-be-persisted",
            "userinfo": self.claims,
        }


def oidc_claims(*, subject="subject-1", username="alice", roles=None):
    return {
        "iss": ISSUER,
        "sub": subject,
        "preferred_username": username,
        "realm_access": {"roles": roles or ["portal-user"]},
    }


def oidc_config(**overrides):
    config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        "PORTAL_LOCAL_AUTH_ENABLED": False,
        "PORTAL_OIDC_ISSUER": ISSUER,
        "PORTAL_OIDC_CLIENT_ID": "proxmox-vm-portal",
        "PORTAL_OIDC_CLIENT_SECRET": "test-client-secret",
        "PORTAL_OIDC_REDIRECT_URI": "https://portal.example.test/auth/oidc/callback",
    }
    config.update(overrides)
    return config


def make_app(fake_oidc, **overrides):
    return create_app(
        oidc_config(**overrides),
        pve_client=FakePVEClient(
            accessible_isos={"pve-a": {"local:iso/debian-12.iso"}}
        ),
        oidc_client=fake_oidc,
    )


def perform_oidc_login(client):
    assert client.get("/auth/oidc/login").status_code == 302
    return client.get("/auth/oidc/callback")


def dispose(app):
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


def test_oidc_login_provisions_user_and_does_not_persist_tokens():
    fake = FakeOIDCClient()
    app = make_app(fake)
    client = app.test_client()

    response = perform_oidc_login(client)

    assert response.status_code == 200
    assert response.get_json()["user"] == {
        "id": 1,
        "username": "alice",
        "role": "user",
        "authentication": "oidc",
        "is_active": True,
        "quota": {"vms": 3, "cpu": 8, "ram_mb": 16384, "disk_gb": 200},
    }
    assert fake.redirect_calls[0][0] == oidc_config()["PORTAL_OIDC_REDIRECT_URI"]
    assert fake.redirect_calls[0][1]["nonce"]
    with client.session_transaction() as portal_session:
        assert "access_token" not in portal_session
        assert "id_token" not in portal_session
        assert portal_session["authentication"] == "oidc"
    with app.app_context():
        user = db.session.scalar(select(User))
        assert user.password_hash is None
        assert user.external_issuer == ISSUER
        assert user.external_subject == "subject-1"
    dispose(app)


def test_oidc_role_is_synchronized_on_each_login():
    fake = FakeOIDCClient()
    app = make_app(fake)
    client = app.test_client()
    assert perform_oidc_login(client).get_json()["user"]["role"] == "user"

    fake.claims = oidc_claims(roles=["portal-admin", "portal-user"])
    response = perform_oidc_login(client)

    assert response.get_json()["user"]["role"] == "admin"
    with app.app_context():
        assert db.session.scalar(select(User)).role == "admin"
    dispose(app)


def test_client_role_claim_is_supported():
    claims = oidc_claims()
    claims.pop("realm_access")
    claims["resource_access"] = {
        "proxmox-vm-portal": {"roles": ["portal-operator"]}
    }
    identity = extract_oidc_identity(
        claims,
        expected_issuer=ISSUER,
        client_id="proxmox-vm-portal",
        role_names={
            "admin": "portal-admin",
            "operator": "portal-operator",
            "user": "portal-user",
        },
    )
    assert identity.role == "operator"


def test_oidc_username_collision_never_links_to_local_account():
    fake = FakeOIDCClient(oidc_claims(username="admin"))
    app = make_app(
        fake,
        PORTAL_LOCAL_AUTH_ENABLED=True,
        PORTAL_ADMIN_USERNAME="admin",
        PORTAL_ADMIN_PASSWORD_HASH=generate_password_hash("a-local-admin-password"),
    )
    client = app.test_client()

    response = perform_oidc_login(client)

    expected = collision_safe_username("admin", ISSUER, "subject-1")
    assert response.get_json()["user"]["username"] == expected
    with app.app_context():
        users = db.session.scalars(select(User).order_by(User.id)).all()
        assert [(user.username, user.auth_provider) for user in users] == [
            ("admin", "local"),
            (expected, "oidc"),
        ]
    dispose(app)


def test_oidc_rejects_missing_role_without_creating_user():
    app = make_app(FakeOIDCClient(oidc_claims(roles=["unrelated-role"])))
    client = app.test_client()

    response = perform_oidc_login(client)

    assert response.status_code == 403
    assert response.get_json() == {"error": "oidc_access_denied"}
    with app.app_context():
        assert db.session.scalar(select(User)) is None
        event = db.session.scalar(select(AuditEvent))
        assert event.outcome == "denied"
        assert event.details == {"reason": "identity_rejected"}
    dispose(app)


@pytest.mark.parametrize(
    "claims",
    [
        {**oidc_claims(), "iss": "https://attacker.example/realms/portal"},
        {**oidc_claims(), "sub": ""},
        {**oidc_claims(), "preferred_username": "invalid username"},
    ],
)
def test_oidc_identity_contract_rejects_invalid_claims(claims):
    with pytest.raises(OIDCIdentityError):
        extract_oidc_identity(
            claims,
            expected_issuer=ISSUER,
            client_id="proxmox-vm-portal",
            role_names={
                "admin": "portal-admin",
                "operator": "portal-operator",
                "user": "portal-user",
            },
        )


def test_disabled_oidc_account_cannot_reauthenticate():
    fake = FakeOIDCClient()
    app = make_app(fake)
    client = app.test_client()
    assert perform_oidc_login(client).status_code == 200
    with app.app_context():
        user = db.session.scalar(select(User))
        user.is_active = False
        db.session.commit()

    response = perform_oidc_login(client)

    assert response.status_code == 403
    assert response.get_json() == {"error": "oidc_access_denied"}
    dispose(app)


def test_oidc_protocol_errors_are_sanitized():
    app = make_app(FakeOIDCClient(error=OAuthError(error="invalid_grant")))
    response = perform_oidc_login(app.test_client())
    assert response.status_code == 401
    assert response.get_json() == {"error": "oidc_authentication_failed"}
    assert "invalid_grant" not in response.get_data(as_text=True)
    dispose(app)


def test_oidc_network_errors_are_sanitized():
    app = make_app(FakeOIDCClient(error=ConnectionError("internal hostname")))
    response = perform_oidc_login(app.test_client())
    assert response.status_code == 503
    assert response.get_json() == {"error": "oidc_unavailable"}
    assert "internal hostname" not in response.get_data(as_text=True)
    dispose(app)


def test_oidc_discovery_errors_are_sanitized():
    app = make_app(
        FakeOIDCClient(redirect_error=ConnectionError("internal hostname"))
    )
    response = app.test_client().get("/auth/oidc/login")
    assert response.status_code == 503
    assert response.get_json() == {"error": "oidc_unavailable"}
    dispose(app)


def test_oidc_callback_requires_login_session():
    app = make_app(FakeOIDCClient())
    response = app.test_client().get("/auth/oidc/callback")
    assert response.status_code == 400
    assert response.get_json() == {"error": "oidc_session_invalid"}
    dispose(app)


def test_local_login_can_be_disabled():
    app = make_app(FakeOIDCClient())
    response = app.test_client().post(
        "/login", json={"username": "admin", "password": "anything"}
    )
    assert response.status_code == 403
    assert response.get_json() == {"error": "local_auth_disabled"}
    dispose(app)


def test_oidc_configuration_is_fail_closed():
    pve = FakePVEClient(accessible_isos={})
    base = {
        "TESTING": True,
        "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    }
    try:
        create_app(
            {**base, "PORTAL_OIDC_ISSUER": ISSUER},
            pve_client=pve,
        )
        raise AssertionError("La configuration incomplète aurait dû être refusée")
    except ValueError as error:
        assert "incomplète" in str(error)

    try:
        create_app(
            {**base, "PORTAL_LOCAL_AUTH_ENABLED": False},
            pve_client=pve,
        )
        raise AssertionError("L'absence de fournisseur aurait dû être refusée")
    except ValueError as error:
        assert "mode d'authentification" in str(error)


@pytest.mark.parametrize(
    "override",
    [
        {
            "PORTAL_OIDC_ROLE_ADMIN": "portal-user",
            "PORTAL_OIDC_ROLE_USER": "portal-user",
        },
        {"PORTAL_OIDC_DEFAULT_QUOTA_CPU": -1},
    ],
)
def test_oidc_rejects_unsafe_role_and_quota_configuration(override):
    with pytest.raises(ValueError):
        make_app(FakeOIDCClient(), **override)


def test_oidc_requires_https_outside_tests():
    config = oidc_config(
        TESTING=False,
        PORTAL_OIDC_ISSUER="http://id.internal/realms/portal",
        PORTAL_OIDC_REDIRECT_URI="http://portal.internal/auth/oidc/callback",
    )
    with pytest.raises(ValueError, match="HTTPS"):
        create_app(config, pve_client=FakePVEClient(accessible_isos={}))


def test_real_authlib_client_is_registered_without_network_call():
    app = create_app(
        oidc_config(PORTAL_LOCAL_AUTH_ENABLED=True),
        pve_client=FakePVEClient(accessible_isos={}),
    )
    remote = app.extensions["oidc_client"]
    assert remote.client_kwargs["code_challenge_method"] == "S256"
    assert remote.client_kwargs["token_endpoint_auth_method"] == "client_secret_basic"
    dispose(app)


def test_oidc_routes_are_hidden_when_not_configured():
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=FakePVEClient(accessible_isos={}),
    )
    client = app.test_client()
    assert client.get("/auth/oidc/login").status_code == 404
    assert client.get("/auth/oidc/callback").status_code == 404
    dispose(app)
