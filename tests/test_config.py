from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.config import MAX_SECRET_BYTES, environment_value
from portal.models import db
from portal.pve import FakePVEClient
from portal.secret_cli import main


def test_environment_value_reads_direct_value(monkeypatch):
    monkeypatch.setenv("PORTAL_TEST_SECRET", "  direct-value  ")
    assert environment_value("PORTAL_TEST_SECRET") == "direct-value"


def test_environment_value_reads_secret_file(monkeypatch, tmp_path: Path):
    secret = tmp_path / "secret"
    secret.write_text("file-value\n", encoding="utf-8")
    monkeypatch.setenv("PORTAL_TEST_SECRET_FILE", str(secret))
    assert environment_value("PORTAL_TEST_SECRET") == "file-value"


def test_environment_value_rejects_ambiguous_sources(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PORTAL_TEST_SECRET", "direct")
    monkeypatch.setenv("PORTAL_TEST_SECRET_FILE", str(tmp_path / "secret"))
    with pytest.raises(ValueError, match="ne peuvent pas être définis ensemble"):
        environment_value("PORTAL_TEST_SECRET")


def test_environment_value_rejects_missing_file(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PORTAL_TEST_SECRET_FILE", str(tmp_path / "missing"))
    with pytest.raises(ValueError, match="Impossible de lire"):
        environment_value("PORTAL_TEST_SECRET")


def test_environment_value_rejects_oversized_file(monkeypatch, tmp_path: Path):
    secret = tmp_path / "secret"
    secret.write_bytes(b"x" * (MAX_SECRET_BYTES + 1))
    monkeypatch.setenv("PORTAL_TEST_SECRET_FILE", str(secret))
    with pytest.raises(ValueError, match="taille autorisée"):
        environment_value("PORTAL_TEST_SECRET")


def test_secret_cli_generates_scrypt_hash(monkeypatch, capsys):
    answers = iter(["a-strong-admin-password", "a-strong-admin-password"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(answers))
    main()
    assert capsys.readouterr().out.startswith("scrypt:")


@pytest.mark.parametrize(
    ("answers", "message"),
    [
        (("a-strong-admin-password", "different-password"), "correspondent pas"),
        (("", ""), "ne peut pas être vide"),
    ],
)
def test_secret_cli_rejects_invalid_password(monkeypatch, answers, message):
    values = iter(answers)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(values))
    with pytest.raises(SystemExit, match=message):
        main()


def test_netbox_configuration_requires_complete_https_settings(monkeypatch):
    base = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
        "PORTAL_ADMIN_USERNAME": "admin",
        "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash("password"),
        "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
    }
    pve = FakePVEClient(accessible_isos={"pve-a": set()})
    monkeypatch.setenv("PORTAL_NETBOX_URL", "https://netbox.example")
    monkeypatch.delenv("PORTAL_NETBOX_API_TOKEN", raising=False)
    with pytest.raises(ValueError, match="doivent être configurés ensemble"):
        create_app(base, pve_client=pve)
    monkeypatch.setenv("PORTAL_NETBOX_API_TOKEN", "token")
    app = create_app(base, pve_client=pve)
    assert app.config["PORTAL_NETBOX_ENABLED"] is True
    assert app.extensions["netbox_client"].base_url == "https://netbox.example"
    with app.app_context():
        db.session.remove()
        db.engine.dispose()
    monkeypatch.setenv("PORTAL_NETBOX_URL", "http://netbox.example")
    with pytest.raises(ValueError, match="doit utiliser HTTPS"):
        create_app({**base, "TESTING": False}, pve_client=pve)
