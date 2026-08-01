from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

_OIDC_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$")


class OIDCIdentityError(ValueError):
    """Les claims validés cryptographiquement ne respectent pas notre contrat."""


@dataclass(frozen=True)
class OIDCIdentity:
    issuer: str
    subject: str
    username: str
    role: str


def extract_oidc_identity(
    claims: dict[str, Any],
    *,
    expected_issuer: str,
    client_id: str,
    role_names: dict[str, str],
) -> OIDCIdentity:
    issuer = claims.get("iss")
    subject = claims.get("sub")
    username = claims.get("preferred_username")
    if issuer != expected_issuer:
        raise OIDCIdentityError("Émetteur OIDC inattendu.")
    if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
        raise OIDCIdentityError("Sujet OIDC invalide.")
    if not isinstance(username, str) or not _OIDC_USERNAME.fullmatch(username):
        raise OIDCIdentityError("Identifiant OIDC invalide.")

    roles = _claim_roles(claims, client_id)
    role = next(
        (
            portal_role
            for portal_role in ("admin", "operator", "user")
            if role_names[portal_role] in roles
        ),
        None,
    )
    if role is None:
        raise OIDCIdentityError("Aucun rôle portail autorisé.")
    return OIDCIdentity(issuer, subject, username.lower(), role)


def collision_safe_username(preferred: str, issuer: str, subject: str) -> str:
    suffix = hashlib.sha256(f"{issuer}\0{subject}".encode()).hexdigest()[:10]
    return f"{preferred[:117]}-{suffix}"


def _claim_roles(claims: dict[str, Any], client_id: str) -> set[str]:
    roles: set[str] = set()
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict) and isinstance(realm_access.get("roles"), list):
        roles.update(role for role in realm_access["roles"] if isinstance(role, str))
    resource_access = claims.get("resource_access")
    client_access = (
        resource_access.get(client_id) if isinstance(resource_access, dict) else None
    )
    if isinstance(client_access, dict) and isinstance(client_access.get("roles"), list):
        roles.update(role for role in client_access["roles"] if isinstance(role, str))
    return roles
