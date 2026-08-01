from pathlib import Path

import pytest

from portal.config import MAX_SECRET_BYTES, environment_value
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
        (("too-short", "too-short"), "au moins 16"),
    ],
)
def test_secret_cli_rejects_invalid_password(monkeypatch, answers, message):
    values = iter(answers)
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(values))
    with pytest.raises(SystemExit, match=message):
        main()
