from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address, IPv4Interface, IPv4Network

from flask import current_app
from sqlalchemy import select

from .guest_secrets import GuestSecretError, decrypt_guest_password
from .models import (
    AuditEvent,
    ProvisioningJob,
    SoftwareModule,
    VMAllocation,
    VMMaintenanceJob,
    VMOperation,
    WorkerHeartbeat,
    db,
)
from .netbox import NetBoxConflict, NetBoxUnavailable
from .notifications import create_notification
from .pve import PVEHTTPError, PVEProtocolError, PVETransportError


def process_next_job(
    pve_client,
    password_pusher=None,
    netbox_client=None,
    *,
    worker_id: str,
    poll_seconds: int = 5,
    lease_seconds: int = 300,
) -> bool:
    """Traite une seule étape; retourne False quand aucune tâche n'est prête."""
    _record_heartbeat(worker_id)
    _recover_stale_jobs(lease_seconds)
    claimed = _claim_job(worker_id)
    if claimed is None:
        processed = _process_next_operation(
            pve_client,
            netbox_client=netbox_client,
            worker_id=worker_id,
            poll_seconds=poll_seconds,
            lease_seconds=lease_seconds,
        )
        if processed:
            return True
        return _process_next_maintenance(
            pve_client,
            worker_id=worker_id,
            poll_seconds=poll_seconds,
            lease_seconds=lease_seconds,
        )
    job_id, phase = claimed
    if phase == "validating":
        _submit_job(pve_client, netbox_client, job_id, poll_seconds)
    else:
        _poll_job(pve_client, password_pusher, netbox_client, job_id, poll_seconds)
    return True


def _record_heartbeat(worker_id: str) -> None:
    normalized_id = worker_id[:128]
    heartbeat = db.session.get(WorkerHeartbeat, normalized_id)
    if heartbeat is None:
        db.session.add(WorkerHeartbeat(worker_id=normalized_id))
    else:
        heartbeat.last_seen_at = datetime.now(UTC)
    db.session.commit()


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


def _submit_job(pve_client, netbox_client, job_id: str, poll_seconds: int) -> None:
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

    if (
        allocation.network_mode == "static"
        and allocation.netbox_prefix_id is not None
        and allocation.netbox_ip_id is None
    ):
        if netbox_client is None:
            _fail(job, "netbox_not_configured")
            return
        try:
            allocation.netbox_ip_id = netbox_client.reserve_ip(
                address=allocation.ipv4_cidr or "",
                description=f"proxmox-vm-portal: {allocation.name} ({allocation.id})",
                dns_name=allocation.name,
                vrf_id=allocation.netbox_vrf_id,
            )
            db.session.commit()
        except NetBoxConflict:
            if allocation.automatic_ip:
                if _advance_automatic_ip(allocation):
                    _reschedule(
                        job, "queued", poll_seconds, "netbox_ip_conflict_retry"
                    )
                else:
                    _fail(job, "ip_pool_exhausted")
                return
            _fail(job, "netbox_ip_conflict")
            return
        except NetBoxUnavailable:
            _reschedule(job, "queued", poll_seconds, "netbox_unavailable")
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
            if not _release_failed_reservation(netbox_client, allocation):
                _attention(job, "netbox_release_failed")
                return
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


def _advance_automatic_ip(allocation: VMAllocation) -> bool:
    profile = allocation.network_profile
    if (
        profile is None
        or profile.pool_start is None
        or profile.pool_end is None
        or allocation.ipv4_cidr is None
    ):
        return False
    current = IPv4Interface(allocation.ipv4_cidr).ip
    start = max(IPv4Address(profile.pool_start), current + 1)
    end = IPv4Address(profile.pool_end)
    excluded = {
        IPv4Address(value)
        for value in profile.excluded_ips.split(",")
        if value
    }
    excluded.add(IPv4Address(profile.gateway))
    used = {
        IPv4Interface(cidr).ip
        for _, cidr in db.session.execute(
            select(VMAllocation.id, VMAllocation.ipv4_cidr).where(
                VMAllocation.network_profile_id == profile.id,
                VMAllocation.id != allocation.id,
                VMAllocation.status != "deleted",
                VMAllocation.ipv4_cidr.is_not(None),
            )
        )
        if cidr is not None
    }
    prefix_length = IPv4Network(profile.cidr).prefixlen
    for numeric_address in range(int(start), int(end) + 1):
        candidate = IPv4Address(numeric_address)
        if candidate not in excluded and candidate not in used:
            allocation.ipv4_cidr = f"{candidate}/{prefix_length}"
            return True
    return False


def _poll_job(pve_client, password_pusher, netbox_client, job_id: str, poll_seconds: int) -> None:
    job = db.session.get(ProvisioningJob, job_id)
    if job is None:
        return
    allocation = job.allocation
    if job.stage == "modules":
        _poll_modules(pve_client, netbox_client, job, poll_seconds)
        return
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
            if not _apply_initial_network_policy(pve_client, job, poll_seconds):
                return
            if not _submit_modules(pve_client, job, poll_seconds):
                return
            _complete(job, netbox_client, poll_seconds)
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
    if not job.guest_password_ciphertext:
        _attention(job, "guest_password_unavailable")
        return

    job.credential_attempts += 1
    try:
        password = decrypt_guest_password(
            job.guest_password_ciphertext,
            current_app.config["PORTAL_SESSION_SECRET"],
        )
    except GuestSecretError:
        _attention(job, "guest_password_unavailable")
        return
    try:
        pve_client.configure_cloud_init_vm(
            node=allocation.node,
            vmid=allocation.vmid,
            cpu=allocation.cpu,
            ram_mb=allocation.ram_mb,
            disk_gb=allocation.disk_gb,
            username=allocation.guest_username,
            password=password,
            network_mode=allocation.network_mode,
            ipv4_cidr=allocation.ipv4_cidr,
            gateway=allocation.gateway,
            dns_servers=allocation.dns_servers.split(",")
            if allocation.dns_servers
            else [],
            bridge=allocation.network_bridge,
            vlan_tag=allocation.vlan_tag,
        )
    except PVETransportError:
        _retry_guest_access(job, poll_seconds, "pve_guest_config_unavailable")
        return
    except (PVEHTTPError, PVEProtocolError):
        _attention(job, "pve_guest_config_failed")
        return
    finally:
        password = ""  # nosec B105
    job.guest_password_ciphertext = None
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


def _apply_initial_network_policy(
    pve_client, job: ProvisioningJob, poll_seconds: int
) -> bool:
    """Applique le confinement avant de déclarer la VM utilisable."""
    allocation = job.allocation
    network_profile = allocation.network_profile
    if allocation.vmid is None:
        _attention(job, "network_policy_invalid")
        return False
    try:
        policy = (
            "isolated"
            if network_profile is not None
            and network_profile.connectivity_mode in {"isolated", "ticket_required"}
            else "sandbox"
        )
        if policy == "sandbox":
            pve_client.set_vm_network_policy(
                allocation.node,
                allocation.vmid,
                policy,
                rules=build_sandbox_firewall_rules(allocation),
            )
        else:
            pve_client.set_vm_network_policy(allocation.node, allocation.vmid, policy)
    except PVETransportError:
        _reschedule(job, "submitted", poll_seconds, "network_policy_unavailable")
        return False
    except (PVEHTTPError, PVEProtocolError):
        _attention(job, "network_policy_failed")
        return False
    allocation.network_policy = policy
    allocation.network_policy_revision = (
        network_profile.sandbox_policy_revision if network_profile is not None else 1
    )
    allocation.network_policy_updated_at = datetime.now(UTC)
    db.session.add(
        AuditEvent(
            actor_user_id=allocation.owner_id,
            action="vm.network_policy.initial",
            target_type="vm",
            target_id=allocation.id,
            outcome="success",
            request_id=job.id,
            details={
                "policy": policy,
                "revision": allocation.network_policy_revision,
                "connectivity_mode": (
                    network_profile.connectivity_mode
                    if network_profile is not None
                    else "sandbox"
                ),
            },
        )
    )
    db.session.commit()
    return True


def build_sandbox_firewall_rules(allocation: VMAllocation) -> list[dict[str, str]]:
    """Construit les seules autorisations réseau du bac à sable."""
    profile = allocation.network_profile
    rules: list[dict[str, str]] = []

    def add(direction: str, label: str, address: str, proto: str, port: str) -> None:
        endpoint = "source" if direction == "in" else "dest"
        rules.append(
            {
                "type": direction,
                "action": "ACCEPT",
                endpoint: address,
                "proto": proto,
                "dport": port,
                "comment": f"portal-sandbox:{label}:{len(rules) + 1}",
            }
        )

    if allocation.network_mode == "dhcp":
        add("out", "dhcp", "0.0.0.0/0", "udp", "67")
        add("in", "dhcp", "0.0.0.0/0", "udp", "68")
    if profile is not None:
        for source in filter(None, profile.sandbox_ssh_sources.split(",")):
            add("in", "ssh", source, "tcp", "22")
        for server in filter(None, profile.dns_servers.split(",")):
            add("out", "dns-udp", server, "udp", "53")
            add("out", "dns-tcp", server, "tcp", "53")
        for server in filter(None, profile.sandbox_ntp_servers.split(",")):
            add("out", "ntp", server, "udp", "123")
        for endpoint in filter(None, profile.sandbox_apt_endpoints.split(",")):
            add("out", "apt", endpoint, "tcp", "443")
        for endpoint in filter(None, profile.sandbox_registry_endpoints.split(",")):
            add("out", "registry", endpoint, "tcp", "443")
        for endpoint in filter(None, profile.sandbox_monitoring_endpoints.split(",")):
            add("in", "zabbix-passive", endpoint, "tcp", "10050")
            add("out", "zabbix-active", endpoint, "tcp", "10051")
    if not rules:
        add("out", "bootstrap", "255.255.255.255/32", "udp", "67")
    return rules


def _selected_modules(allocation: VMAllocation) -> list[SoftwareModule]:
    selected = set(allocation.software_modules or [])
    return list(
        db.session.scalars(
            select(SoftwareModule)
            .where(
                SoftwareModule.enabled.is_(True),
                (SoftwareModule.required.is_(True) | SoftwareModule.slug.in_(selected)),
            )
            .order_by(SoftwareModule.slug)
        ).all()
    )


def _module_command(modules: list[SoftwareModule]) -> list[str] | None:
    preinstalled: list[str] = []
    packages: list[str] = []
    images: list[str] = []
    for module in modules:
        artifacts = [value for value in module.artifacts.split("\n") if value]
        if module.install_mode == "preinstalled":
            preinstalled.extend(artifacts)
        elif module.install_mode == "apt":
            packages.extend(artifacts)
        else:
            images.extend(artifacts)
    commands = [
        f"dpkg-query -W -f='${{Status}}' {package} | grep -q 'install ok installed'"
        for package in preinstalled
    ]
    if packages:
        commands.extend(
            [
                "apt-get update",
                "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
                + " ".join(packages),
            ]
        )
    if images:
        commands.append("command -v docker >/dev/null")
        commands.extend(
            f"docker image inspect {image} >/dev/null 2>&1 || docker pull {image}"
            for image in images
        )
    return ["/bin/sh", "-ceu", "; ".join(commands)] if commands else None


def _submit_modules(pve_client, job: ProvisioningJob, poll_seconds: int) -> bool:
    allocation = job.allocation
    command = _module_command(_selected_modules(allocation))
    if command is None:
        return True
    if allocation.vmid is None:
        _attention(job, "module_install_invalid")
        return False
    job.module_attempts += 1
    try:
        job.guest_pid = pve_client.guest_exec(
            allocation.node, allocation.vmid, command
        )
    except (PVETransportError, PVEHTTPError):
        if job.module_attempts < 30:
            _reschedule(job, "submitted", poll_seconds, "guest_agent_not_ready")
        else:
            _attention(job, "guest_agent_not_ready")
        return False
    except PVEProtocolError:
        _attention(job, "module_install_submission_invalid")
        return False
    job.stage = "modules"
    _reschedule(job, "submitted", poll_seconds)
    return False


def _poll_modules(
    pve_client, netbox_client, job: ProvisioningJob, poll_seconds: int
) -> None:
    allocation = job.allocation
    if allocation.vmid is None or job.guest_pid is None:
        _attention(job, "module_install_invalid")
        return
    try:
        result = pve_client.guest_exec_status(
            allocation.node, allocation.vmid, job.guest_pid
        )
    except PVETransportError:
        _reschedule(job, "submitted", poll_seconds, "guest_agent_unavailable")
        return
    except (PVEHTTPError, PVEProtocolError):
        _attention(job, "module_install_status_unknown")
        return
    if not result["exited"]:
        _reschedule(job, "submitted", poll_seconds)
    elif result.get("exitcode") != 0:
        _attention(job, "module_install_failed")
    else:
        _complete(job, netbox_client, poll_seconds)


def _complete(job: ProvisioningJob, netbox_client=None, poll_seconds: int = 5) -> None:
    allocation = job.allocation
    if allocation.netbox_ip_id is not None:
        if netbox_client is None:
            _attention(job, "netbox_not_configured")
            return
        try:
            netbox_client.activate_ip(allocation.netbox_ip_id)
        except NetBoxUnavailable:
            _reschedule(job, "submitted", poll_seconds, "netbox_activation_failed")
            return
    job.status = "succeeded"
    job.error_code = None
    job.completed_at = datetime.now(UTC)
    job.locked_at = None
    job.locked_by = None
    job.allocation.status = (
        "running" if job.stage in {"start", "modules"} else "accepted"
    )
    _audit(job, "success", {"name": job.allocation.name})
    _notify_provisioning(job, "succeeded")
    db.session.commit()


def _release_failed_reservation(netbox_client, allocation) -> bool:
    if allocation.netbox_ip_id is None:
        return True
    if netbox_client is None:
        return False
    try:
        netbox_client.release_ip(allocation.netbox_ip_id)
    except NetBoxUnavailable:
        return False
    allocation.netbox_ip_id = None
    db.session.commit()
    return True


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
    job.guest_password_ciphertext = None
    _audit(job, "failure", {"error_code": error_code})
    _notify_provisioning(job, "failed")
    db.session.commit()


def _attention(job: ProvisioningJob, error_code: str) -> None:
    job.status = "attention"
    job.error_code = error_code
    job.completed_at = datetime.now(UTC)
    job.locked_at = None
    job.locked_by = None
    _audit(job, "failure", {"error_code": error_code, "manual_review": True})
    _notify_provisioning(job, "attention")
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


def _notify_provisioning(job: ProvisioningJob, status: str) -> None:
    content = {
        "succeeded": (
            "provisioning_succeeded",
            "Machine prête",
            f"La machine {job.allocation.name} est prête.",
        ),
        "failed": (
            "provisioning_failed",
            "Échec du provisionnement",
            f"La création de {job.allocation.name} a échoué.",
        ),
        "attention": (
            "provisioning_attention",
            "Vérification requise",
            f"La création de {job.allocation.name} nécessite une vérification administrative.",
        ),
    }
    kind, title, message = content[status]
    create_notification(
        user_id=job.allocation.owner_id,
        kind=kind,
        title=title,
        message=message,
        dedup_key=f"provisioning:{job.id}:{status}",
        target_type="vm",
        target_id=job.allocation_id,
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
            _notify_provisioning(job, "attention")
        job.locked_at = None
        job.locked_by = None
    if jobs:
        db.session.commit()


def _process_next_operation(
    pve_client,
    *,
    netbox_client=None,
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
        _poll_operation(pve_client, netbox_client, operation_id, poll_seconds)
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
    if allocation.vmid is None:
        _fail_operation(operation, "lifecycle_invalid_state")
        return

    try:
        actual_status = pve_client.get_vm_status(allocation.node, allocation.vmid)
    except PVETransportError:
        _attention_operation(operation, "pve_status_unknown")
        return
    except (PVEHTTPError, PVEProtocolError):
        _attention_operation(operation, "pve_status_unknown")
        return

    allocation.status = actual_status
    if operation.action == "start" and actual_status == "running":
        _complete_operation(operation)
        return
    if operation.action == "stop" and actual_status == "stopped":
        _complete_operation(operation)
        return
    if operation.action == "delete" and actual_status == "running":
        _fail_operation(operation, "vm_must_be_stopped")
        return
    if operation.action == "reboot" and actual_status != "running":
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


def _poll_operation(pve_client, netbox_client, operation_id: str, poll_seconds: int) -> None:
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
        _complete_operation(operation, netbox_client, poll_seconds)
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


def _complete_operation(
    operation: VMOperation, netbox_client=None, poll_seconds: int = 5
) -> None:
    allocation = operation.allocation
    if operation.action == "delete" and allocation.netbox_ip_id is not None:
        if netbox_client is None:
            _attention_operation(operation, "netbox_not_configured")
            return
        try:
            netbox_client.release_ip(allocation.netbox_ip_id)
        except NetBoxUnavailable:
            _reschedule_operation(
                operation, "submitted", poll_seconds, "netbox_release_failed"
            )
            return
        allocation.netbox_ip_id = None
    allocation.status = {
        "start": "running",
        "stop": "stopped",
        "reboot": "running",
        "delete": "deleted",
    }[operation.action]
    if operation.action == "delete":
        if (
            operation.actor_user_id is None
            and allocation.lifecycle_quarantined_at is not None
        ):
            create_notification(
                user_id=allocation.owner_id,
                kind="lifecycle_deleted",
                title="Machine de test supprimée",
                message=(
                    f"La machine {allocation.name} a été supprimée automatiquement "
                    "après son expiration et son délai de grâce."
                ),
                dedup_key=f"lifecycle-deleted:{allocation.id}",
                target_type="vm",
                target_id=allocation.id,
            )
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


_APT_COMMON = """set -eu
export LC_ALL=C DEBIAN_FRONTEND=noninteractive
apt-get -q -o DPkg::Lock::Timeout=60 update
printf '__PORTAL_PENDING_BEGIN__\\n'
apt list --upgradable 2>/dev/null || true
printf '__PORTAL_PENDING_END__\\n'
"""

_APT_SCAN_SCRIPT = _APT_COMMON + """if test -e /run/reboot-required; then
  printf '__PORTAL_REBOOT_REQUIRED__\\n'
fi
"""

_APT_UPDATE_SCRIPT = _APT_COMMON + """apt-get -y -q \\
  -o DPkg::Lock::Timeout=60 \\
  -o Dpkg::Options::=--force-confold upgrade
printf '__PORTAL_REMAINING_BEGIN__\\n'
apt list --upgradable 2>/dev/null || true
printf '__PORTAL_REMAINING_END__\\n'
if test -e /run/reboot-required; then
  printf '__PORTAL_REBOOT_REQUIRED__\\n'
fi
"""


def _process_next_maintenance(
    pve_client, *, worker_id: str, poll_seconds: int, lease_seconds: int
) -> bool:
    _recover_stale_maintenance(lease_seconds)
    claimed = _claim_maintenance(worker_id)
    if claimed is None:
        return False
    job_id, phase = claimed
    if phase == "submitting":
        _submit_maintenance(pve_client, job_id, poll_seconds)
    else:
        _poll_maintenance(pve_client, job_id, poll_seconds)
    return True


def _claim_maintenance(worker_id: str) -> tuple[str, str] | None:
    now = datetime.now(UTC)
    job = db.session.scalar(
        select(VMMaintenanceJob)
        .where(
            VMMaintenanceJob.status.in_(("queued", "submitted")),
            VMMaintenanceJob.available_at <= now,
        )
        .order_by(VMMaintenanceJob.available_at, VMMaintenanceJob.created_at)
        .with_for_update(skip_locked=True)
    )
    if job is None:
        db.session.rollback()
        return None
    job.status = "submitting" if job.status == "queued" else "submitted"
    job.locked_at = now
    job.locked_by = worker_id[:128]
    db.session.commit()
    return job.id, job.status


def _submit_maintenance(pve_client, job_id: str, poll_seconds: int) -> None:
    job = db.session.get(VMMaintenanceJob, job_id)
    if job is None:
        return
    allocation = job.allocation
    if allocation.vmid is None or allocation.status != "running":
        _fail_maintenance(job, "maintenance_vm_not_running")
        return
    if allocation.network_policy == "isolated":
        _fail_maintenance(job, "maintenance_network_isolated")
        return
    command = [
        "/bin/sh",
        "-c",
        _APT_SCAN_SCRIPT if job.action == "scan" else _APT_UPDATE_SCRIPT,
    ]
    try:
        job.guest_pid = pve_client.guest_exec(
            allocation.node, allocation.vmid, command
        )
    except PVEHTTPError as error:
        if error.status is not None and 400 <= error.status < 500:
            _fail_maintenance(job, "maintenance_agent_rejected")
        else:
            _attention_maintenance(job, "maintenance_submission_unknown")
        return
    except (PVETransportError, PVEProtocolError):
        _attention_maintenance(job, "maintenance_submission_unknown")
        return
    job.status = "submitted"
    job.available_at = datetime.now(UTC) + timedelta(seconds=poll_seconds)
    job.locked_at = None
    job.locked_by = None
    db.session.commit()


def _poll_maintenance(pve_client, job_id: str, poll_seconds: int) -> None:
    job = db.session.get(VMMaintenanceJob, job_id)
    if job is None:
        return
    allocation = job.allocation
    if allocation.vmid is None or job.guest_pid is None:
        _attention_maintenance(job, "maintenance_guest_pid_missing")
        return
    try:
        result = pve_client.guest_exec_status(
            allocation.node, allocation.vmid, job.guest_pid
        )
    except PVETransportError:
        _reschedule_maintenance(job, poll_seconds)
        return
    except (PVEHTTPError, PVEProtocolError):
        _attention_maintenance(job, "maintenance_status_unknown")
        return
    if not result["exited"]:
        _reschedule_maintenance(job, poll_seconds)
        return
    stdout = result.get("out-data", "")
    stderr = result.get("err-data", "")
    if result.get("exitcode") != 0:
        job.output_excerpt = (stdout + "\n" + stderr).strip()[-8000:] or None
        _fail_maintenance(job, "maintenance_command_failed")
        return
    job.output_excerpt = None
    job.report = _parse_apt_report(stdout, action=job.action)
    job.status = "succeeded"
    job.error_code = None
    job.completed_at = datetime.now(UTC)
    job.locked_at = None
    job.locked_by = None
    _audit_maintenance(job, "success")
    db.session.commit()


def _parse_apt_report(output: str, *, action: str) -> dict[str, object]:
    def section(start: str, end: str) -> list[str]:
        if start not in output or end not in output:
            return []
        content = output.split(start, 1)[1].split(end, 1)[0]
        packages: list[str] = []
        for line in content.splitlines():
            normalized = line.strip()
            if not normalized or normalized == "Listing..." or "/" not in normalized:
                continue
            name = normalized.split("/", 1)[0]
            if name and name not in packages:
                packages.append(name[:255])
        return packages[:500]

    pending = section("__PORTAL_PENDING_BEGIN__", "__PORTAL_PENDING_END__")
    remaining = section("__PORTAL_REMAINING_BEGIN__", "__PORTAL_REMAINING_END__")
    return {
        "available_count": len(pending),
        "available_packages": pending,
        "updated_count": len(set(pending) - set(remaining)) if action == "update" else 0,
        "remaining_count": len(remaining) if action == "update" else len(pending),
        "remaining_packages": remaining if action == "update" else pending,
        "reboot_required": "__PORTAL_REBOOT_REQUIRED__" in output,
    }


def _reschedule_maintenance(job: VMMaintenanceJob, delay_seconds: int) -> None:
    job.status = "submitted"
    job.available_at = datetime.now(UTC) + timedelta(seconds=delay_seconds)
    job.locked_at = None
    job.locked_by = None
    db.session.commit()


def _fail_maintenance(job: VMMaintenanceJob, error_code: str) -> None:
    job.status = "failed"
    job.error_code = error_code
    job.completed_at = datetime.now(UTC)
    job.locked_at = None
    job.locked_by = None
    _audit_maintenance(job, "failure")
    db.session.commit()


def _attention_maintenance(job: VMMaintenanceJob, error_code: str) -> None:
    job.status = "attention"
    job.error_code = error_code
    job.completed_at = datetime.now(UTC)
    job.locked_at = None
    job.locked_by = None
    _audit_maintenance(job, "failure")
    db.session.commit()


def _audit_maintenance(job: VMMaintenanceJob, outcome: str) -> None:
    report = job.report or {}
    db.session.add(
        AuditEvent(
            actor_user_id=job.actor_user_id,
            action=f"vm.maintenance.{job.action}",
            target_type="vm",
            target_id=job.allocation_id,
            outcome=outcome,
            request_id=job.id,
            details={
                "error_code": job.error_code,
                "available_count": report.get("available_count"),
                "updated_count": report.get("updated_count"),
                "reboot_required": report.get("reboot_required"),
            },
        )
    )


def _recover_stale_maintenance(lease_seconds: int) -> None:
    cutoff = datetime.now(UTC) - timedelta(seconds=lease_seconds)
    jobs = db.session.scalars(
        select(VMMaintenanceJob).where(
            VMMaintenanceJob.status == "submitting",
            VMMaintenanceJob.locked_at < cutoff,
        )
    ).all()
    for job in jobs:
        job.status = "attention"
        job.error_code = "worker_crashed_during_maintenance"
        job.completed_at = datetime.now(UTC)
        job.locked_at = None
        job.locked_by = None
        _audit_maintenance(job, "failure")
    if jobs:
        db.session.commit()
