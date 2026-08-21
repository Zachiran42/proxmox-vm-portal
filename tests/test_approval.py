from sqlalchemy import select
from werkzeug.security import generate_password_hash

from portal import create_app
from portal.jobs import process_next_job
from portal.models import AuditEvent, ProvisioningJob, VMAllocation, db
from portal.pve import FakePVEClient

ADMIN_PASSWORD = "correct-horse-battery-staple"


def make_app():
    pve_client = FakePVEClient(
        accessible_isos={"pve-a": {"local:iso/debian-12.iso"}}
    )
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "PORTAL_ADMIN_USERNAME": "admin",
            "PORTAL_ADMIN_PASSWORD_HASH": generate_password_hash(ADMIN_PASSWORD),
            "PORTAL_SESSION_SECRET": "test-session-secret-that-is-long-enough",
        },
        pve_client=pve_client,
    )
    return app, pve_client


def login(client):
    response = client.post(
        "/login", json={"username": "admin", "password": ADMIN_PASSWORD}
    )
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.get_json()["csrf_token"]


def request_vm(client, name):
    return client.post(
        "/api/vms",
        json={
            "name": name,
            "node": "pve-a",
            "profile": "debian-12",
            "cpu": 2,
            "ram_mb": 4096,
            "disk_gb": 40,
        },
    )


def test_pending_request_waits_for_explicit_approval_before_worker():
    app, pve_client = make_app()
    client = app.test_client()
    login(client)
    enabled = client.patch(
        "/api/admin/settings", json={"vm_approval_required": True}
    )
    assert enabled.status_code == 200

    created = request_vm(client, "approval-vm")
    assert created.status_code == 202
    assert created.get_json()["status"] == "pending_approval"
    vm_id = created.get_json()["vm_id"]
    assert client.get("/api/notifications").get_json()["notifications"][0][
        "kind"
    ] == "approval_requested"

    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        assert allocation.status == "pending_approval"
        assert allocation.approval_status == "pending"
        assert allocation.job.status == "approval_pending"
        assert process_next_job(
            pve_client,
            worker_id="approval-worker",
            poll_seconds=0,
            lease_seconds=60,
        ) is False
    assert pve_client.requests == []

    overview = client.get("/api/admin/operations").get_json()
    assert overview["approvals"]["pending"] == 1
    assert overview["approvals"]["items"][0]["id"] == vm_id

    approved = client.post(
        f"/api/admin/vms/{vm_id}/approval",
        json={"action": "approve", "reason": "Capacité validée"},
    )
    assert approved.status_code == 200
    assert approved.get_json()["status"] == "queued"
    notification_kinds = {
        item["kind"]
        for item in client.get("/api/notifications").get_json()["notifications"]
    }
    assert notification_kinds == {"approval_requested", "approval_approved"}
    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        assert allocation.status == "queued"
        assert allocation.approval_status == "approved"
        assert allocation.approval_decided_by.username == "admin"
        assert allocation.job.status == "queued"
        assert db.session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "vm.approval.approve"
            )
        ) is not None


def test_rejection_requires_reason_releases_quota_and_erases_guest_secret():
    app, _pve_client = make_app()
    client = app.test_client()
    login(client)
    client.patch("/api/admin/settings", json={"vm_approval_required": True})
    created = request_vm(client, "rejected-vm")
    vm_id = created.get_json()["vm_id"]
    with app.app_context():
        job = db.session.scalar(
            select(ProvisioningJob).where(ProvisioningJob.allocation_id == vm_id)
        )
        job.guest_password_ciphertext = "temporary-encrypted-value"
        db.session.commit()

    missing_reason = client.post(
        f"/api/admin/vms/{vm_id}/approval", json={"action": "reject"}
    )
    assert missing_reason.status_code == 400
    rejected = client.post(
        f"/api/admin/vms/{vm_id}/approval",
        json={"action": "reject", "reason": "Demande hors périmètre"},
    )
    assert rejected.status_code == 200
    assert rejected.get_json()["status"] == "rejected"
    assert client.get("/api/notifications").get_json()["notifications"][0][
        "kind"
    ] == "approval_rejected"
    assert client.get("/api/me").get_json()["usage"]["vms"] == 0
    assert client.post(
        f"/api/admin/vms/{vm_id}/approval",
        json={"action": "approve"},
    ).get_json()["error"] == "approval_already_decided"
    public_job = client.get("/api/jobs").get_json()["jobs"][0]
    assert public_job["vm"]["approval"]["reason"] == "Demande hors périmètre"

    with app.app_context():
        allocation = db.session.get(VMAllocation, vm_id)
        assert allocation.status == "rejected"
        assert allocation.approval_status == "rejected"
        assert allocation.approval_reason == "Demande hors périmètre"
        assert allocation.job.status == "failed"
        assert allocation.job.error_code == "approval_rejected"
        assert allocation.job.guest_password_ciphertext is None


def test_approval_endpoint_strictly_validates_payload_and_unknown_vm():
    app, _pve_client = make_app()
    client = app.test_client()
    login(client)
    assert client.post(
        "/api/admin/vms/missing/approval", json={"action": "approve"}
    ).status_code == 404
    for payload, field in (
        (None, "body"),
        ({"action": "approve", "extra": True}, "body"),
        ({"action": "later"}, "action"),
        ({"action": "approve", "reason": 42}, "reason"),
        ({"action": "approve", "reason": "x" * 501}, "reason"),
    ):
        response = client.post("/api/admin/vms/missing/approval", json=payload)
        assert response.status_code == 400
        assert field in response.get_json()["errors"]

    invalid_setting = client.patch(
        "/api/admin/settings", json={"vm_approval_required": "yes"}
    )
    assert invalid_setting.status_code == 400
