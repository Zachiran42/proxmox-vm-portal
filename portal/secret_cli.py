from __future__ import annotations

import getpass

from werkzeug.security import generate_password_hash


def main() -> None:
    password = getpass.getpass("Mot de passe administrateur: ")
    confirmation = getpass.getpass("Confirmation: ")
    if password != confirmation:
        raise SystemExit("Les mots de passe ne correspondent pas.")
    if not password:
        raise SystemExit("Le mot de passe ne peut pas être vide.")
    print(generate_password_hash(password, method="scrypt"))


if __name__ == "__main__":  # pragma: no cover - point d'entrée interactif
    main()
