from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
import requests
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.password_pusher import (
    PasswordPusherClient,
    PasswordPusherHTTPError,
    PasswordPusherProtocolError,
    PasswordPusherTransportError,
)
from portal.pve import FakePVEClient


def client(**overrides):
    values = {
        "base_url": "https://pwpush.example/",
        "api_token": "test-api-token",
        "expire_after_days": 2,
        "expire_after_views": 1,
    }
    values.update(overrides)
    return PasswordPusherClient(**values)


def response(status=201, data=None):
    result = Mock(status_code=status)
    result.json.return_value = (
        {"html_url": "https://pwpush.example/p/secret-token"}
        if data is None
        else data
    )
    return result


def test_push_uses_v2_json_api_tls_and_disables_redirects():
    with patch("portal.password_pusher.requests.post", return_value=response()) as post:
        pushed = client(ca_bundle="/etc/ssl/internal-ca.pem").push(
            "generated-secret", note="VM test"
        )

    assert pushed.url == "https://pwpush.example/p/secret-token"
    assert pushed.expire_after_days == 2
    call = post.call_args
    assert call.args == ("https://pwpush.example/api/v2/pushes.json",)
    assert call.kwargs["json"] == {
        "push": {
            "payload": "generated-secret",
            "note": "VM test",
            "expire_after_days": 2,
            "expire_after_views": 1,
        }
    }
    assert call.kwargs["headers"]["Authorization"] == "Bearer test-api-token"
    assert call.kwargs["verify"] == "/etc/ssl/internal-ca.pem"
    assert call.kwargs["allow_redirects"] is False
    assert call.kwargs["timeout"] == 10


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"base_url": "http://pwpush.example"}, "HTTPS"),
        ({"base_url": "https://user@pwpush.example"}, "HTTPS"),
        ({"base_url": "https://pwpush.example?target=other"}, "HTTPS"),
        ({"api_token": ""}, "TOKEN"),
        ({"expire_after_days": 0}, "DAYS"),
        ({"expire_after_views": 11}, "VIEWS"),
    ],
)
def test_client_rejects_unsafe_configuration(overrides, message):
    with pytest.raises(ValueError, match=message):
        client(**overrides)


def test_transport_and_http_errors_never_include_secret_or_token():
    with patch(
        "portal.password_pusher.requests.post",
        side_effect=requests.ConnectionError("generated-secret test-api-token"),
    ):
        with pytest.raises(PasswordPusherTransportError) as transport:
            client().push("generated-secret", note="VM")
    assert "generated-secret" not in str(transport.value)
    assert "test-api-token" not in str(transport.value)

    with patch(
        "portal.password_pusher.requests.post", return_value=response(status=403)
    ):
        with pytest.raises(PasswordPusherHTTPError) as http:
            client().push("generated-secret", note="VM")
    assert http.value.status == 403
    assert "generated-secret" not in str(http.value)


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"html_url": "http://pwpush.example/p/token"},
        {"html_url": "not-a-url"},
    ],
)
def test_push_rejects_invalid_credential_link(data):
    with patch(
        "portal.password_pusher.requests.post", return_value=response(data=data)
    ):
        with pytest.raises(PasswordPusherProtocolError):
            client().push("generated-secret", note="VM")


def test_push_builds_link_from_valid_url_token_for_self_hosted_response():
    with patch(
        "portal.password_pusher.requests.post",
        return_value=response(data={"url_token": "valid_token-123"}),
    ):
        pushed = client().push("generated-secret", note="VM")
    assert pushed.url == "https://pwpush.example/p/valid_token-123"


def test_push_rejects_invalid_json():
    invalid = response()
    invalid.json.side_effect = requests.JSONDecodeError("invalid", "x", 0)
    with patch("portal.password_pusher.requests.post", return_value=invalid):
        with pytest.raises(PasswordPusherProtocolError):
            client().push("generated-secret", note="VM")


def app_config(**overrides):
    config = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "PORTAL_ADMIN_USERNAME": "admin",
        "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(
            "correct-horse-battery-staple"
        ),
        "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
    }
    config.update(overrides)
    return config


def test_app_requires_password_pusher_url_and_token_together():
    pve = FakePVEClient(accessible_isos={})
    with pytest.raises(ValueError, match="configurés ensemble"):
        create_app(
            app_config(PORTAL_PWPUSH_URL="https://pwpush.example"),
            pve_client=pve,
        )
    with pytest.raises(ValueError, match="configurés ensemble"):
        create_app(
            app_config(PORTAL_PWPUSH_API_TOKEN="token-only"),
            pve_client=pve,
        )


def test_app_builds_password_pusher_client_from_secure_configuration():
    app = create_app(
        app_config(
            PORTAL_PWPUSH_URL="https://pwpush.example",
            PORTAL_PWPUSH_API_TOKEN="test-token",
            PORTAL_PWPUSH_EXPIRE_DAYS=2,
            PORTAL_PWPUSH_EXPIRE_VIEWS=1,
        ),
        pve_client=FakePVEClient(accessible_isos={}),
    )
    configured = app.extensions["password_pusher_client"]
    assert configured.base_url == "https://pwpush.example"
    assert configured.expire_after_days == 2
    with app.app_context():
        from portal.models import db

        db.session.remove()
        db.engine.dispose()
