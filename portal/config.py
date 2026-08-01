from __future__ import annotations

import os
from pathlib import Path

MAX_SECRET_BYTES = 64 * 1024


def environment_value(name: str, default: str = "", *, strip: bool = True) -> str:
    """Lit NAME ou NAME_FILE, sans autoriser deux sources ambiguës."""
    value = os.environ.get(name)
    file_name = os.environ.get(f"{name}_FILE")
    if value is not None and file_name is not None:
        raise ValueError(f"{name} et {name}_FILE ne peuvent pas être définis ensemble.")
    if file_name is not None:
        path = Path(file_name)
        try:
            if path.stat().st_size > MAX_SECRET_BYTES:
                raise ValueError(f"Le fichier {name}_FILE dépasse la taille autorisée.")
            value = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ValueError(f"Impossible de lire {name}_FILE.") from error
    if value is None:
        value = default
    return value.strip() if strip else value
