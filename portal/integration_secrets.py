from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


class IntegrationSecretError(Exception):
    pass


def _cipher(application_secret: str, purpose: str) -> Fernet:
    material = f"proxmox-vm-portal:{purpose}\0{application_secret}".encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(material).digest())
    return Fernet(key)


def encrypt_integration_secret(
    plaintext: str, application_secret: str, *, purpose: str
) -> str:
    return (
        _cipher(application_secret, purpose)
        .encrypt(plaintext.encode("utf-8"))
        .decode("ascii")
    )


def decrypt_integration_secret(
    ciphertext: str, application_secret: str, *, purpose: str
) -> str:
    try:
        return (
            _cipher(application_secret, purpose)
            .decrypt(ciphertext.encode("ascii"))
            .decode("utf-8")
        )
    except (InvalidToken, UnicodeError, ValueError) as error:
        raise IntegrationSecretError(
            "Le secret d'intégration chiffré est illisible."
        ) from error
