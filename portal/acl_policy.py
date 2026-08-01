from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class ACLPolicyError(ValueError):
    pass


def _privileges(value: Any) -> set[str]:
    if isinstance(value, dict):
        return {
            str(name)
            for name, enabled in value.items()
            if enabled not in (False, 0, None, "0")
        }
    if isinstance(value, list):
        return {str(name) for name in value}
    raise ACLPolicyError("Format de privilèges Proxmox non reconnu.")


def normalize_permissions(document: Any) -> dict[str, set[str]]:
    if isinstance(document, dict) and set(document) == {"data"}:
        document = document["data"]
    if isinstance(document, dict):
        permissions = {
            str(path): _privileges(privileges)
            for path, privileges in document.items()
        }
    elif isinstance(document, list):
        permissions = {}
        for entry in document:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise ACLPolicyError("Entrée de permission Proxmox invalide.")
            raw = entry.get("privileges", entry.get("privs"))
            permissions[entry["path"]] = _privileges(raw)
    else:
        raise ACLPolicyError("Rapport de permissions Proxmox invalide.")
    if not permissions:
        raise ACLPolicyError("Le rapport de permissions Proxmox est vide.")
    return permissions


def verify_permissions(report: Any, policy: Any) -> list[str]:
    permissions = normalize_permissions(report)
    if not isinstance(policy, dict):
        raise ACLPolicyError("Politique ACL invalide.")
    allowed_raw = policy.get("allowed_paths")
    required_raw = policy.get("required_paths", {})
    forbidden_raw = policy.get("forbidden_privileges", [])
    if not isinstance(allowed_raw, dict) or not isinstance(required_raw, dict):
        raise ACLPolicyError("allowed_paths et required_paths doivent être des objets.")
    allowed = {str(path): _privileges(value) for path, value in allowed_raw.items()}
    required = {str(path): _privileges(value) for path, value in required_raw.items()}
    forbidden = _privileges(forbidden_raw)
    errors: list[str] = []

    for path, actual in sorted(permissions.items()):
        if path not in allowed:
            errors.append(f"Chemin ACL non autorisé: {path}")
            continue
        excessive = actual - allowed[path]
        if excessive:
            errors.append(
                f"Privilèges excessifs sur {path}: {', '.join(sorted(excessive))}"
            )
        forbidden_found = actual & forbidden
        if forbidden_found:
            errors.append(
                f"Privilèges interdits sur {path}: {', '.join(sorted(forbidden_found))}"
            )

    for path, expected in sorted(required.items()):
        missing = expected - permissions.get(path, set())
        if missing:
            errors.append(
                f"Privilèges requis absents sur {path}: {', '.join(sorted(missing))}"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Vérifie un export pveum contre une politique ACL stricte."
    )
    parser.add_argument("report", type=Path)
    parser.add_argument("policy", type=Path)
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        errors = verify_permissions(report, policy)
    except (OSError, json.JSONDecodeError, ACLPolicyError) as exception:
        print(f"ERREUR: {exception}")
        return 2
    if errors:
        for policy_error in errors:
            print(f"ECHEC: {policy_error}")
        return 1
    print("OK: les permissions effectives respectent la politique ACL.")
    return 0


if __name__ == "__main__":  # pragma: no cover - point d'entrée CLI
    raise SystemExit(main())
