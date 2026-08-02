from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from .models import AuditEvent, ProvisioningJob, VMOperation, db
from .password_pusher import PasswordPusherError
from .pve import PVEHTTPError, PVEProtocolError, PVETransportError


def process_next_job(
    pve_client,
    password_pusher=None,
    *,
    worker_id: str,
    poll_seconds: int = 5,
    lease_seconds: int = 300,
) -> bool:
    """Traite une seule étape; retourne False quand aucune tâche n'est prête."""
    _recover_stale_jobs(lease_seconds)
    claimed = _claim_job(worker_id)
    if claimed is None:
        return _process_next_operation(
            pve_client,
            worker_id=worker_id,
            poll_seconds=poll_seconds,
            lease_seconds=lease_seconds,
        )
    job_id, phase = claimed
    if phase == "validating":
        _submit_job(pve_client, job_id, poll_seconds)
    else:
        _poll_job(pve_client, password_pusher, job_id, poll_seconds)
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
    if job is None:
        return
    allocation = job.allocation
    profile = allocation.profile
    if profile is None or not profile.enabled:
        _fail(job, "image_profile_unavailable")
        return
    try:
        if profile.source_type == "cloud_init":
            if profile.template_node is None or profile.template_vmid is None:
                _fail(job, "image_profile_invalid")
                return
            available = pve_client.is_template_available(
                profile.template_node, profile.template_vmid
            )
        else:
            if allocation.iso is None:
                _fail(job, "image_profile_invalid")
                return
            available = pve_client.is_iso_available(allocation.node, allocation.iso)
    except (PVETransportError, PVEHTTPError):
        _reschedule(job, "queued", poll_seconds, "pve_inventory_unavailable")
        return
    except PVEProtocolError:
        _fail(job, "pve_inventory_invalid")
        return
    if not available:
        _fail(
            job,
            "template_unavailable"
            if profile.source_type == "cloud_init"
            else "iso_unavailable",
        )
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
        "source_type": profile.source_type,
        "template_node": profile.template_node,
        "template_vmid": profile.template_vmid,
    }
    try:
        submission = pve_client.create_vm(request_payload)
    except PVEHTTPError as error:
        status = error.status
        if status is not None and 400 <= status < 500 and status not in {408, 429}:
            _fail(job, "pve_submission_rejected")
        else:
            _attention(job, "pve_submission_unknown")
        return
    except (PVETransportError, PVEProtocolError):
        _attention(job, "pve_submission_unknown")
        return

    allocation.upstream_request_id = submission.upid
    allocation.vmid = submission.vmid
    allocation.status = "provisioning"
    job.upstream_node = (
        profile.template_node
        if profile.source_type == "cloud_init"
        else allocation.node
    )
    _reschedule(job, "submitted", poll_seconds)


def _poll_job(pve_client, password_pusher, job_id: str, poll_seconds: int) -> None:
    job = db.session.get(ProvisioningJob, job_id)
    if job is None:
        return
    allocation = job.allocation
    if not allocation.upstream_request_id or not job.upstream_node:
        _attention(job, "missing_upstream_task")
        return
    try:
        result = pve_client.get_task_status(
            job.upstream_node, allocation.upstream_request_id
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
        profile = allocation.profile
        if profile is None:
            _attention(job, "image_profile_unavailable")
        elif job.stage == "create" and profile.source_type == "cloud_init":
            _bootstrap_cloud_init_access(
                pve_client, password_pusher, job, poll_seconds
            )
        else:
            _complete(job)
        return
    if job.stage == "start":
        _attention(job, "pve_start_failed")
    else:
        _fail(job, "pve_task_failed")


def _bootstrap_cloud_init_access(
    pve_client, password_pusher, job: ProvisioningJob, poll_seconds: int
) -> None:
    allocation = job.allocation
    if not allocation.guest_username or allocation.vmid is None:
        _attention(job, "guest_bootstrap_invalid")
        return
    if password_pusher is None:
        _attention(job, "password_pusher_not_configured")
        return

    if not allocation.credential_url:
        job.credential_attempts += 1
        password = secrets.token_urlsafe(24)
        try:
            pve_client.configure_cloud_init_vm(
                node=allocation.node,
                vmid=allocation.vmid,
                cpu=allocation.cpu,
                ram_mb=allocation.ram_mb,
                disk_gb=allocation.disk_gb,
                username=allocation.guest_username,
                password=password,
            )
        except PVETransportError:
            _retry_guest_access(job, poll_seconds, "pve_guest_config_unavailable")
            return
        except (PVEHTTPError, PVEProtocolError):
            _attention(job, "pve_guest_config_failed")
            return
        try:
            pushed = password_pusher.push(
                password, note=f"Accès initial à la VM {allocation.name}"
            )
        except PasswordPusherError:
            _retry_guest_access(job, poll_seconds, "password_pusher_unavailable")
            return
        allocation.credential_url = pushed.url
        allocation.credential_created_at = datetime.now(UTC)
        allocation.credential_expire_days = pushed.expire_after_days
        allocation.credential_expire_views = pushed.expire_after_views
        db.session.commit()

    job.status = "submitting"
    job.error_code = None
    db.session.commit()
    try:
        upid = pve_client.start_vm(allocation.node, allocation.vmid)
    except (PVETransportError, PVEHTTPError, PVEProtocolError):
        _attention(job, "pve_start_unknown")
        return
    job.stage = "start"
    job.upstream_node = allocation.node
    allocation.upstream_request_id = upid
    _reschedule(job, "submitted", poll_seconds)


def _retry_guest_access(
    job: ProvisioningJob, poll_seconds: int, error_code: str
) -> None:
    if job.credential_attempts >= 5:
        _attention(job, error_code)
    else:
        _reschedule(job, "submitted", poll_seconds, error_code)


def _complete(job: ProvisioningJob) -> None:
    job.status = "succeeded"
    job.error_code = None
    job.completed_at = datetime.now(UTC)
    job.locked_at = None
    job.locked_by = None
    job.allocation.status = "running" if job.stage == "start" else "accepted"
    _audit(job, "success", {"name": job.allocation.name})
    db.session.commit()


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


def _process_next_operation(
    pve_client,
    *,
    worker_id: str,
    poll_seconds: int,
    lease_seconds: int,
) -> bool:
    _recover_stale_operations(lease_seconds)
    claimed = _claim_operation(worker_id)
    if claimed is None:
        return False
    operation_id, phase = claimed
    if phase == "submitting":
        _submit_operation(pve_client, operation_id, poll_seconds)
    else:
        _poll_operation(pve_client, operation_id, poll_seconds)
    return True


def _claim_operation(worker_id: str) -> tuple[str, str] | None:
    now = datetime.now(UTC)
    operation = db.session.scalar(
        select(VMOperation)
        .where(
            VMOperation.status.in_(("queued", "submitted")),
            VMOperation.available_at <= now,
        )
        .order_by(VMOperation.available_at, VMOperation.created_at)
        .with_for_update(skip_locked=True)
    )
    if operation is None:
        db.session.rollback()
        return None
    operation.status = "submitting" if operation.status == "queued" else "polling"
    operation.locked_at = now
    operation.locked_by = worker_id[:128]
    db.session.commit()
    return operation.id, operation.status


def _submit_operation(pve_client, operation_id: str, poll_seconds: int) -> None:
    operation = db.session.get(VMOperation, operation_id)
    if operation is None:
        return
    allocation = operation.allocation
    allowed_states = {
        "start": {"accepted", "stopped"},
        "stop": {"accepted", "running"},
        "reboot": {"running"},
        "delete": {"accepted", "stopped"},
    }
    if allocation.vmid is None or allocation.status not in allowed_states[operation.action]:
        _fail_operation(operation, "lifecycle_invalid_state")
        return

    method = getattr(pve_client, f"{operation.action}_vm")
    try:
        upid = method(allocation.node, allocation.vmid)
    except PVEHTTPError as error:
        if error.status is not None and 400 <= error.status < 500 and error.status not in {408, 429}:
            _fail_operation(operation, "pve_operation_rejected")
        else:
            _attention_operation(operation, "pve_operation_unknown")
        return
    except (PVETransportError, PVEProtocolError):
        _attention_operation(operation, "pve_operation_unknown")
        return

    operation.upstream_node = allocation.node
    operation.upstream_request_id = upid
    _reschedule_operation(operation, "submitted", poll_seconds)


def _poll_operation(pve_client, operation_id: str, poll_seconds: int) -> None:
    operation = db.session.get(VMOperation, operation_id)
    if operation is None:
        return
    if not operation.upstream_node or not operation.upstream_request_id:
        _attention_operation(operation, "missing_upstream_task")
        return
    try:
        result = pve_client.get_task_status(
            operation.upstream_node, operation.upstream_request_id
        )
    except PVETransportError:
        _reschedule_operation(
            operation, "submitted", poll_seconds, "pve_temporarily_unavailable"
        )
        return
    except (PVEHTTPError, PVEProtocolError):
        _attention_operation(operation, "pve_task_status_unknown")
        return
    if result["status"] == "running":
        _reschedule_operation(operation, "submitted", poll_seconds)
    elif result.get("exitstatus") == "OK":
        _complete_operation(operation)
    else:
        _fail_operation(operation, "pve_operation_failed")


def _reschedule_operation(
    operation: VMOperation,
    status: str,
    delay_seconds: int,
    error_code: str | None = None,
) -> None:
    operation.status = status
    operation.error_code = error_code
    operation.available_at = datetime.now(UTC) + timedelta(seconds=delay_seconds)
    operation.locked_at = None
    operation.locked_by = None
    db.session.commit()


def _complete_operation(operation: VMOperation) -> None:
    allocation = operation.allocation
    allocation.status = {
        "start": "running",
        "stop": "stopped",
        "reboot": "running",
        "delete": "deleted",
    }[operation.action]
    if operation.action == "delete":
        allocation.credential_url = None
        allocation.credential_created_at = None
        allocation.credential_expire_days = None
        allocation.credential_expire_views = None
    operation.status = "succeeded"
    operation.error_code = None
    operation.completed_at = datetime.now(UTC)
    operation.locked_at = None
    operation.locked_by = None
    _audit_operation(operation, "success", {"name": allocation.name})
    db.session.commit()


def _fail_operation(operation: VMOperation, error_code: str) -> None:
    operation.status = "failed"
    operation.error_code = error_code
    operation.completed_at = datetime.now(UTC)
    operation.locked_at = None
    operation.locked_by = None
    _audit_operation(operation, "failure", {"error_code": error_code})
    db.session.commit()


def _attention_operation(operation: VMOperation, error_code: str) -> None:
    operation.status = "attention"
    operation.error_code = error_code
    operation.completed_at = datetime.now(UTC)
    operation.locked_at = None
    operation.locked_by = None
    _audit_operation(
        operation,
        "failure",
        {"error_code": error_code, "manual_review": True},
    )
    db.session.commit()


def _audit_operation(
    operation: VMOperation, outcome: str, details: dict[str, object]
) -> None:
    db.session.add(
        AuditEvent(
            actor_user_id=operation.actor_user_id,
            action=f"vm.{operation.action}",
            target_type="vm",
            target_id=operation.allocation_id,
            outcome=outcome,
            request_id=operation.id,
            details=details,
        )
    )


def _recover_stale_operations(lease_seconds: int) -> None:
    cutoff = datetime.now(UTC) - timedelta(seconds=lease_seconds)
    operations = db.session.scalars(
        select(VMOperation).where(
            VMOperation.status.in_(("submitting", "polling")),
            VMOperation.locked_at < cutoff,
        )
    ).all()
    for operation in operations:
        if operation.status == "polling":
            operation.status = "submitted"
        else:
            operation.status = "attention"
            operation.error_code = "worker_crashed_during_operation"
            operation.completed_at = datetime.now(UTC)
            _audit_operation(
                operation,
                "failure",
                {"reason": "worker_crashed_during_operation", "manual_review": True},
            )
        operation.locked_at = None
        operation.locked_by = None
    if operations:
        db.session.commit()
