from __future__ import annotations

import socket
import ssl
from urllib.error import URLError

import pytest
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.pve import FakePVEClient, PVEHTTPError, PVEProtocolError, PVETransportError


@pytest.fixture
def pve_client():
    return FakePVEClient(accessible_isos={"pve-a": {"local:iso/debian-12.iso"}})


@pytest.fixture
def app(pve_client):
    return create_app(
        {
            "TESTING": True,
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("correct-horse-battery-staple"),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve_client,
    )


def payload():
    return {"name": "web-01", "node": "pve-a", "iso": "local:iso/debian-12.iso", "cpu": 2, "ram_mb": 4096, "disk_gb": 40}


def login(client):
    response = client.post("/login", json={"username": "admin", "password": "correct-horse-battery-staple"})
    if response.status_code == 200:
        client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]
    return response


def test_vm_creation_requires_local_login(app, pve_client):
    client = app.test_client()
    assert client.post("/api/vms", json=payload()).status_code == 401
    assert login(client).status_code == 200
    assert client.post("/api/vms", json=payload()).status_code == 202
    assert client.post("/logout").status_code == 200
    assert client.post("/api/vms", json=payload()).status_code == 401
    assert pve_client.requests == [payload()]


def test_vm_creation_and_logout_require_csrf_token(app, pve_client):
    client = app.test_client()
    response = login(client)
    csrf_token = response.get_json()["csrf_token"]
    del client.environ_base["HTTP_X_CSRF_TOKEN"]

    assert client.post("/api/vms", json=payload()).status_code == 403
    assert client.post("/logout").status_code == 403
    assert pve_client.requests == []

    client.environ_base["HTTP_X_CSRF_TOKEN"] = csrf_token
    assert client.post("/api/vms", json=payload()).status_code == 202
    assert client.post("/logout").status_code == 200


def test_invalid_login_and_session_security(app):
    response = app.test_client().post("/login", json={"username": "admin", "password": "invalid"})
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_credentials"}
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_SECURE"] is True


def test_security_headers_are_added(app):
    response = app.test_client().get("/")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")


def test_missing_authentication_configuration_prevents_startup(pve_client):
    with pytest.raises(ValueError, match="PORTAL_ADMIN"):
        create_app({"TESTING": True}, pve_client=pve_client)


@pytest.mark.parametrize(("error", "status"), [(PVETransportError("network failed"), 503), (PVEProtocolError("bad JSON"), 502), (PVEHTTPError(500, "PVE token=secret"), 502)])
def test_pve_errors_are_sanitized(app, error, status):
    client = app.test_client()
    login(client)
    app.extensions["pve_client"].is_iso_available = lambda node, iso: (_ for _ in ()).throw(error)
    response = client.post("/api/vms", json=payload())
    assert response.status_code == status
    assert response.get_json() == {"error": "pve_unavailable"}
    assert "secret" not in response.get_data(as_text=True)


def test_body_over_64_kib_is_json_413(app):
    response = app.test_client().post("/api/vms", data=b"x" * (64 * 1024 + 1), content_type="application/json")
    assert response.status_code == 413
    assert response.get_json() == {"error": "payload_too_large"}


@pytest.mark.parametrize("error", [URLError("refused"), socket.timeout(), ssl.SSLError("TLS")])
def test_pve_transport_exceptions_are_wrapped(error):
    from unittest.mock import patch
    from portal.pve import PVEClient
    client = PVEClient("https://pve.example/api2/json", "portal@pve!token", "not-a-real-secret")
    with patch("portal.pve.urlopen", side_effect=error):
        with pytest.raises(PVETransportError):
            client._request("/cluster/nextid")


def test_invalid_pve_json_is_wrapped_as_protocol_error():
    from unittest.mock import MagicMock, patch
    from portal.pve import PVEClient
    client = PVEClient("https://pve.example/api2/json", "portal@pve!token", "not-a-real-secret")
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b"not-json"
    with patch("portal.pve.urlopen", return_value=response):
        with pytest.raises(PVEProtocolError):
            client._request("/cluster/nextid")
