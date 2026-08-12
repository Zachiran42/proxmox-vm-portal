import pytest

from portal.guest_secrets import (
    GuestSecretError,
    decrypt_guest_password,
    encrypt_guest_password,
)


def test_guest_password_round_trip_preserves_all_characters():
    password = " espaces / accents éè ! 🔐 "
    ciphertext = encrypt_guest_password(password, "application-secret")
    assert password not in ciphertext
    assert decrypt_guest_password(ciphertext, "application-secret") == password


def test_guest_password_rejects_wrong_application_key():
    ciphertext = encrypt_guest_password("password", "first-key")
    with pytest.raises(GuestSecretError):
        decrypt_guest_password(ciphertext, "another-key")
