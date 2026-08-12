from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


class GuestSecretError(Exception):
    pass


def _cipher(application_secret: str) -> Fernet:
    key = base64.urlsafe_b64encode(
        hashlib.sha256(application_secret.encode("utf-8")).digest()
    )
    return Fernet(key)


def encrypt_guest_password(password: str, application_secret: str) -> str:
    return _cipher(application_secret).encrypt(password.encode("utf-8")).decode("ascii")


def decrypt_guest_password(ciphertext: str, application_secret: str) -> str:
    try:
        return _cipher(application_secret).decrypt(ciphertext.encode("ascii")).decode(
            "utf-8"
        )
    except (InvalidToken, UnicodeError, ValueError) as error:
        raise GuestSecretError("Le secret invité chiffré est illisible.") from error
