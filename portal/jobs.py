from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from .models import AuditEvent, ProvisioningJob, db
from .pve import PVEHTTPError, PVEProtocolError, PVETransportError


def process_next_job(
    pve_client,
    *,
    worker_id: str,
    poll_seconds: int = 5,
    lease_seconds: int = 300,
) -> bool:
    """Traite une seule étape; retourne False quand aucune tâche n'est prête."""
    _recover_stale_jobs(lease_seconds)
    claimed = _claim_job(worker_id)
    if claimed is None:
        return False
    job_id, phase = claimed
    if phase == "validating":
        _submit_job(pve_client, job_id, poll_seconds)
    else:
        _poll_job(pve_client, job_id, poll_seconds)
    return True


def _claim_job(worker_id: str) -> tuple[str, str] | None:
    now = datetime.now(UTC)
    job = db.session.scalar(
        select(ProvisioningJob)
        .where(
            ProvisioningJob.status.in_(("queued", "submitted")),
            ProvisioningJob.available_at <= now,
        )
        .order_by(ProvisioningJob.available_at, ProvisioningJob.created_at)
        .with_for_update(skip_locked=True)
    )
    if job is None:
        db.session.rollback()
        return None
    job.status = "validating" if job.status == "queued" else "polling"
    job.attempts += 1
    job.locked_at = now
    job.locked_by = worker_id[:128]
    db.session.commit()
    return job.id, job.status


def _submit_job(pve_client, job_id: str, poll_seconds: int) -> None:
    job = db.session.get(ProvisioningJob, job_id)
    assert job is not None
    allocation = job.allocation
    profile = allocation.profile
    if profile is None or not profile.enabled:
        _fail(job, "image_profile_unavailable")
        return
    try:
        available = pve_client.is_iso_available(allocation.node, allocation.iso)
    except (PVETransportError, PVEHTTPError):
        _reschedule(job, "queued", poll_seconds, "pve_inventory_unavailable")
        return
    except PVEProtocolError:
        _fail(job, "pve_inventory_invalid")
        return
    if not available:
        _fail(job, "iso_unavailable")
        return

    job.status = "submitting"
    job.error_code = None
    allocation.status = "provisioning"
    db.session.commit()
    request_payload = {
        "name": allocation.name,
        "node": allocation.node,
        "iso": allocation.iso,
        "cpu": allocation.cpu,
        "ram_mb": allocation.ram_mb,
        "disk_gb": allocation.disk_gb,
    }
    try:
        upid = pve_client.create_vm(request_payload)
    except PVEHTTPError as error:
        if 400 <= error.status < 500 and error.status not in {408, 429}:
            _fail(job, "pve_submission_rejected")
        else:
            _attention(job, "pve_submission_unknown")
        return
    except (PVETransportError, PVEProtocolError):
        _attention(job, "pve_submission_unknown")
        return

    allocation.upstream_request_id = upid
    allocation.status = "provisioning"
    _reschedule(job, "submitted", poll_seconds)


def _poll_job(pve_client, job_id: str, poll_seconds: int) -> None:
    job = db.session.get(ProvisioningJob, job_id)
    assert job is not None
    allocation = job.allocation
    if not allocation.upstream_request_id:
        _attention(job, "missing_upstream_task")
        return
    try:
        result = pve_client.get_task_status(
            allocation.node, allocation.upstream_request_id
        )
    except PVETransportError:
        _reschedule(job, "submitted", poll_seconds, "pve_temporarily_unavailable")
        return
    except (PVEHTTPError, PVEProtocolError):
        _attention(job, "pve_task_status_unknown")
        return
    if result["status"] == "running":
        _reschedule(job, "submitted", poll_seconds)
        return
    if result.get("exitstatus") == "OK":
        job.status = "succeeded"
        job.error_code = None
        job.completed_at = datetime.now(UTC)
        job.locked_at = None
        job.locked_by = None
        allocation.status = "accepted"
        _audit(job, "success", {"name": allocation.name})
        db.session.commit()
        return
    _fail(job, "pve_task_failed")


def _reschedule(
    job: ProvisioningJob,
    status: str,
    delay_seconds: int,
    error_code: str | None = None,
) -> None:
    job.status = status
    job.error_code = error_code
    job.available_at = datetime.now(UTC) + timedelta(seconds=delay_seconds)
    job.locked_at = None
    job.locked_by = None
    db.session.commit()


def _fail(job: ProvisioningJob, error_code: str) -> None:
    job.status = "failed"
    job.error_code = error_code
    job.completed_at = datetime.now(UTC)
    job.locked_at = None
    job.locked_by = None
    job.allocation.status = "failed"
    _audit(job, "failure", {"error_code": error_code})
    db.session.commit()


def _attention(job: ProvisioningJob, error_code: str) -> None:
    job.status = "attention"
    job.error_code = error_code
    job.completed_at = datetime.now(UTC)
    job.locked_at = None
    job.locked_by = None
    _audit(job, "failure", {"error_code": error_code, "manual_review": True})
    db.session.commit()


def _audit(job: ProvisioningJob, outcome: str, details: dict) -> None:
    db.session.add(
        AuditEvent(
            actor_user_id=job.allocation.owner_id,
            action="vm.provision",
            target_type="vm",
            target_id=job.allocation_id,
            outcome=outcome,
            request_id=job.id,
            details=details,
        )
    )


def _recover_stale_jobs(lease_seconds: int) -> None:
    cutoff = datetime.now(UTC) - timedelta(seconds=lease_seconds)
    jobs = db.session.scalars(
        select(ProvisioningJob).where(
            ProvisioningJob.status.in_(("validating", "submitting", "polling")),
            ProvisioningJob.locked_at < cutoff,
        )
    ).all()
    for job in jobs:
        if job.status == "validating":
            job.status = "queued"
        elif job.status == "polling":
            job.status = "submitted"
        else:
            job.status = "attention"
            job.error_code = "worker_crashed_during_submission"
            job.completed_at = datetime.now(UTC)
            _audit(
                job,
                "failure",
                {"reason": "worker_crashed_during_submission"},
            )
        job.locked_at = None
        job.locked_by = None
    if jobs:
        db.session.commit()
