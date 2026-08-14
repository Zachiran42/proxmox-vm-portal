from __future__ import annotations

import pytest
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.models import User, db
from portal.pve import FakePVEClient


@pytest.fixture
def app():
    application = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(
                "correct-horse-battery-staple"
            ),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=FakePVEClient(
            accessible_isos={"pve-a": {"local:iso/debian-12.iso"}}
        ),
    )
    yield application
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


def test_portal_shell_loads_self_hosted_assets_and_strict_csp(app):
    response = app.test_client().get("/")
    html = response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'lang="fr"' in html
    assert "Images de machines" in html
    assert "Mes machines" in html
    assert 'id="vm-form"' in html
    assert 'id="vm-action-dialog"' in html
    assert 'id="vm-confirm-name"' in html
    assert 'id="service-grid"' in html
    assert 'id="incident-list"' in html
    assert 'id="incident-dialog"' in html
    assert 'href="/api/admin/audit-events.csv"' in html
    assert 'id="job-list"' in html
    assert 'id="show-archived"' in html
    assert 'id="vm-details-dialog"' in html
    assert 'id="vm-details-ipv4"' in html
    assert 'id="vm-operation-history"' in html
    assert 'id="vm-guest-password"' in html
    assert 'id="guest-password-min-length"' in html
    assert 'id="admin-view"' in html
    assert 'id="user-form"' in html
    assert 'id="first-password-dialog"' in html
    assert 'id="audit-list"' in html
    assert 'data-local-auth="true"' in html
    assert 'data-oidc="false"' in html
    assert 'src="/static/portal.js"' in html
    assert 'href="/static/portal.css"' in html
    assert "<script>" not in html
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp


def test_frontend_assets_are_served_with_expected_types(app):
    client = app.test_client()
    css = client.get("/static/portal.css")
    javascript = client.get("/static/portal.js")

    assert css.status_code == 200
    assert css.mimetype == "text/css"
    assert "prefers-reduced-motion" in css.get_data(as_text=True)
    assert javascript.status_code == 200
    assert javascript.mimetype == "text/javascript"
    assert "innerHTML" not in javascript.get_data(as_text=True)


def test_authenticated_session_can_restore_its_csrf_token(app):
    client = app.test_client()
    login = client.post(
        "/login",
        json={
            "username": "admin",
            "password": "correct-horse-battery-staple",
        },
    )

    restored = client.get("/api/me")

    assert restored.status_code == 200
    assert restored.get_json()["csrf_token"] == login.get_json()["csrf_token"]
    assert restored.get_json()["user"]["role"] == "admin"


def test_temporary_admin_password_must_be_changed_before_access(app):
    with app.app_context():
        admin = db.session.execute(select(User).where(User.username == "admin")).scalar_one()
        admin.must_change_password = True
        db.session.commit()

    client = app.test_client()
    login = client.post(
        "/login",
        json={"username": "admin", "password": "correct-horse-battery-staple"},
    )
    csrf_token = login.get_json()["csrf_token"]
    assert login.get_json()["user"]["must_rotate_credentials"] is True
    assert client.get("/api/image-profiles").status_code == 403

    changed = client.post(
        "/api/me/password",
        headers={"X-CSRF-Token": csrf_token},
        json={"password": "x"},
    )
    assert changed.status_code == 200
    assert changed.get_json()["user"]["must_rotate_credentials"] is False
    assert client.get("/api/image-profiles").status_code == 200
