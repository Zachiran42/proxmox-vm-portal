import json
from pathlib import Path

import pytest

from portal.acl_policy import (
    ACLPolicyError,
    main,
    normalize_permissions,
    verify_permissions,
)


@pytest.fixture
def policy():
    return {
        "allowed_paths": {
            "/": ["Sys.Audit"],
            "/pool/portal": ["VM.Allocate", "VM.Audit"],
        },
        "required_paths": {"/pool/portal": ["VM.Allocate"]},
        "forbidden_privileges": ["Permissions.Modify"],
    }


def test_normalizes_pveum_permission_shapes():
    assert normalize_permissions({"data": {"/": {"Sys.Audit": 1, "Sys.Modify": 0}}}) == {
        "/": {"Sys.Audit"}
    }
    assert normalize_permissions(
        [{"path": "/pool/portal", "privileges": ["VM.Allocate"]}]
    ) == {"/pool/portal": {"VM.Allocate"}}


@pytest.mark.parametrize("document", [None, {}, [], [{"privileges": []}]])
def test_rejects_invalid_permission_reports(document):
    with pytest.raises(ACLPolicyError):
        normalize_permissions(document)


def test_rejects_invalid_privileges_and_policies(policy):
    with pytest.raises(ACLPolicyError, match="privilèges"):
        normalize_permissions({"/": "Sys.Audit"})
    with pytest.raises(ACLPolicyError, match="Politique"):
        verify_permissions({"/": {"Sys.Audit": 1}}, [])
    with pytest.raises(ACLPolicyError, match="allowed_paths"):
        verify_permissions({"/": {"Sys.Audit": 1}}, {"allowed_paths": []})


def test_accepts_least_privilege_report(policy):
    report = {
        "/": {"Sys.Audit": 1},
        "/pool/portal": {"VM.Allocate": 1, "VM.Audit": 1},
    }
    assert verify_permissions(report, policy) == []


def test_versioned_example_policy_is_valid():
    policy_path = (
        Path(__file__).parents[1] / "deploy" / "proxmox" / "acl-policy.example.json"
    )
    versioned_policy = json.loads(policy_path.read_text(encoding="utf-8"))
    minimal_report = versioned_policy["required_paths"]
    assert verify_permissions(minimal_report, versioned_policy) == []


def test_reports_unknown_excessive_forbidden_and_missing_permissions(policy):
    report = {
        "/": {"Sys.Audit": 1, "Permissions.Modify": 1},
        "/vms": {"VM.Allocate": 1},
    }
    errors = verify_permissions(report, policy)
    assert any("excessifs" in error for error in errors)
    assert any("interdits" in error for error in errors)
    assert any("non autorisé" in error for error in errors)
    assert any("requis absents" in error for error in errors)


def test_cli_returns_expected_statuses(tmp_path, policy, capsys):
    policy_path = tmp_path / "policy.json"
    report_path = tmp_path / "report.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    report_path.write_text(
        json.dumps({"/": {"Sys.Audit": 1}, "/pool/portal": {"VM.Allocate": 1}}),
        encoding="utf-8",
    )
    assert main([str(report_path), str(policy_path)]) == 0
    assert "OK:" in capsys.readouterr().out

    report_path.write_text(json.dumps({"/": {"Sys.Modify": 1}}), encoding="utf-8")
    assert main([str(report_path), str(policy_path)]) == 1
    assert "ECHEC:" in capsys.readouterr().out

    report_path.write_text("not-json", encoding="utf-8")
    assert main([str(report_path), str(policy_path)]) == 2
