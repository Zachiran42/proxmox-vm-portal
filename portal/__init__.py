from __future__ import annotations

import os
import secrets
import uuid
from datetime import timedelta
from functools import wraps
from hmac import compare_digest
from typing import Any

import click
from flask import Flask, g, jsonify, request, session
from flask_migrate import Migrate
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash

from .models import ACTIVE_VM_STATUSES, AuditEvent, User, VMAllocation, db
from .pve import PVEClient, PVEHTTPError, PVEProtocolError, PVETransportError
from .validation import (
    UserCreateRequest,
    ValidationError,
    VMRequest,
    validate_node_name,
)


def _bool_environment(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() not in {"0", "false", "no"}


def create_app(test_config: dict | None = None, *, pve_client=None) -> Flask:
    """Crée l'application; l'accès PVE peut être injecté pendant les tests."""
    app = Flask(__name__)
    app.config.from_mapping(
        JSON_SORT_KEYS=True,
        MAX_CONTENT_LENGTH=64 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_bool_environment(
            "PORTAL_SESSION_COOKIE_SECURE", True
        ),
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        PORTAL_ADMIN_USERNAME=os.environ.get("PORTAL_ADMIN_USERNAME", "").strip(),
        PORTAL_ADMIN_PASSWORD_HASH=os.environ.get(
            "PORTAL_ADMIN_PASSWORD_HASH", ""
        ).strip(),
        PORTAL_SESSION_SECRET=os.environ.get("PORTAL_SESSION_SECRET", ""),
        PORTAL_DUMMY_PASSWORD_HASH=generate_password_hash(
            secrets.token_urlsafe(32), method="scrypt"
        ),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "PORTAL_DATABASE_URL", "sqlite:///portal.db"
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )
    if test_config:
        app.config.update(test_config)
        if test_config.get("TESTING") and "SQLALCHEMY_DATABASE_URI" not in test_config:
            app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite://"

    if not app.config.get("PORTAL_SESSION_SECRET"):
        raise ValueError(
            "Variable d'environnement d'authentification manquante: "
            "PORTAL_SESSION_SECRET"
        )
    app.secret_key = app.config["PORTAL_SESSION_SECRET"]

    db.init_app(app)
    Migrate(app, db)
    if app.config.get("TESTING"):
        _initialize_test_database(app)

    client = pve_client or PVEClient.from_environment()
    app.extensions["pve_client"] = client

    @app.before_request
    def initialize_request_context():
        g.request_id = str(uuid.uuid4())
        if (
            request.content_length is not None
            and request.content_length > app.config["MAX_CONTENT_LENGTH"]
        ):
            return jsonify(error="payload_too_large"), 413
        return None

    @app.errorhandler(RequestEntityTooLarge)
    def payload_too_large(_error):
        return jsonify(error="payload_too_large"), 413

    @app.errorhandler(PVETransportError)
    def pve_transport_failure(_error):
        return jsonify(error="pve_unavailable"), 503

    @app.errorhandler(PVEProtocolError)
    @app.errorhandler(PVEHTTPError)
    def pve_upstream_failure(_error):
        return jsonify(error="pve_unavailable"), 502

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return response

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user_id = session.get("user_id")
            user = db.session.get(User, user_id) if type(user_id) is int else None
            if user is None or not user.is_active:
                session.clear()
                return jsonify(error="authentication_required"), 401
            g.current_user = user
            return view(*args, **kwargs)

        return wrapped

    def role_required(*roles: str):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if g.current_user.role not in roles:
                    _add_audit(
                        action="authorization.denied",
                        target_type="endpoint",
                        target_id=request.endpoint,
                        outcome="denied",
                        actor_user_id=g.current_user.id,
                        details={"required_roles": sorted(roles)},
                    )
                    db.session.commit()
                    return jsonify(error="forbidden"), 403
                return view(*args, **kwargs)

            return wrapped

        return decorator

    def csrf_protected(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            expected = session.get("csrf_token")
            supplied = request.headers.get("X-CSRF-Token", "")
            if (
                not isinstance(expected, str)
                or not isinstance(supplied, str)
                or not compare_digest(expected, supplied)
            ):
                return jsonify(error="csrf_validation_failed"), 403
            return view(*args, **kwargs)

        return wrapped

    @app.cli.command("bootstrap-admin")
    def bootstrap_admin_command():
        """Crée le premier administrateur après `flask db upgrade`."""
        username = app.config["PORTAL_ADMIN_USERNAME"]
        password_hash = app.config["PORTAL_ADMIN_PASSWORD_HASH"]
        if not username or not password_hash:
            raise click.ClickException(
                "PORTAL_ADMIN_USERNAME et PORTAL_ADMIN_PASSWORD_HASH sont requis."
            )
        if db.session.scalar(select(User.id).limit(1)) is not None:
            raise click.ClickException(
                "La base contient déjà un utilisateur; bootstrap refusé."
            )
        db.session.add(
            User(
                username=username,
                password_hash=password_hash,
                role="admin",
                quota_vms=100,
                quota_cpu=512,
                quota_ram_mb=1048576,
                quota_disk_gb=102400,
            )
        )
        db.session.commit()
        click.echo(f"Administrateur {username!r} créé.")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/")
    def home():
        return (
            "<!doctype html><title>Portail Proxmox</title>"
            "<h1>Portail Proxmox</h1>"
            "<p>MVP de provisionnement sécurisé.</p>"
        )

    @app.post("/login")
    def login():
        credentials = request.get_json(silent=True)
        username = credentials.get("username") if isinstance(credentials, dict) else None
        password = credentials.get("password") if isinstance(credentials, dict) else None
        user = (
            db.session.scalar(select(User).where(User.username == username))
            if isinstance(username, str)
            else None
        )
        password_hash = (
            user.password_hash
            if user is not None
            else app.config["PORTAL_DUMMY_PASSWORD_HASH"]
        )
        password_valid = isinstance(password, str) and check_password_hash(
            password_hash, password
        )
        if user is None or not user.is_active or not password_valid:
            _add_audit(
                action="authentication.login",
                target_type="user",
                target_id=username if isinstance(username, str) else None,
                outcome="failure",
            )
            db.session.commit()
            return jsonify(error="invalid_credentials"), 401

        session.clear()
        session["user_id"] = user.id
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        _add_audit(
            action="authentication.login",
            target_type="user",
            target_id=str(user.id),
            outcome="success",
            actor_user_id=user.id,
        )
        db.session.commit()
        return jsonify(
            status="authenticated",
            csrf_token=session["csrf_token"],
            user=user.public_dict(),
        )

    @app.post("/logout")
    @login_required
    @csrf_protected
    def logout():
        _add_audit(
            action="authentication.logout",
            target_type="user",
            target_id=str(g.current_user.id),
            outcome="success",
            actor_user_id=g.current_user.id,
        )
        db.session.commit()
        session.clear()
        return jsonify(status="logged_out")

    @app.get("/api/me")
    @login_required
    def me():
        return jsonify(user=g.current_user.public_dict(), usage=_quota_usage(g.current_user.id))

    @app.get("/api/nodes")
    @login_required
    def list_nodes():
        return jsonify(nodes=client.list_nodes())

    @app.get("/api/nodes/<node>/isos")
    @login_required
    def list_isos(node: str):
        try:
            validate_node_name(node)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400
        return jsonify(node=node, isos=client.list_isos(node))

    @app.get("/api/admin/users")
    @login_required
    @role_required("admin")
    def list_users():
        users = db.session.scalars(select(User).order_by(User.username)).all()
        return jsonify(users=[user.public_dict() for user in users])

    @app.post("/api/admin/users")
    @login_required
    @role_required("admin")
    @csrf_protected
    def create_user():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            user_request = UserCreateRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400

        user = User(
            username=user_request.username,
            password_hash=generate_password_hash(
                user_request.password, method="scrypt"
            ),
            role=user_request.role,
            quota_vms=user_request.quota_vms,
            quota_cpu=user_request.quota_cpu,
            quota_ram_mb=user_request.quota_ram_mb,
            quota_disk_gb=user_request.quota_disk_gb,
        )
        db.session.add(user)
        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            _add_audit(
                action="user.create",
                target_type="user",
                target_id=user_request.username,
                outcome="failure",
                actor_user_id=g.current_user.id,
                details={"reason": "username_conflict"},
            )
            db.session.commit()
            return jsonify(errors={"username": "Identifiant déjà utilisé."}), 409

        _add_audit(
            action="user.create",
            target_type="user",
            target_id=str(user.id),
            outcome="success",
            actor_user_id=g.current_user.id,
            details={"role": user.role},
        )
        db.session.commit()
        return jsonify(user=user.public_dict()), 201

    @app.get("/api/admin/audit-events")
    @login_required
    @role_required("admin")
    def list_audit_events():
        events = db.session.scalars(
            select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100)
        ).all()
        return jsonify(events=[event.public_dict() for event in events])

    @app.post("/api/vms")
    @login_required
    @csrf_protected
    def request_vm():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            vm_request = VMRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400

        try:
            iso_available = client.is_iso_available(vm_request.node, vm_request.iso)
        except (PVETransportError, PVEProtocolError, PVEHTTPError):
            _add_audit(
                action="vm.create",
                target_type="vm",
                target_id=vm_request.name,
                outcome="failure",
                actor_user_id=g.current_user.id,
                details={"reason": "pve_inventory_failure"},
            )
            db.session.commit()
            raise

        if not iso_available:
            _add_audit(
                action="vm.create",
                target_type="vm",
                target_id=vm_request.name,
                outcome="denied",
                actor_user_id=g.current_user.id,
                details={"reason": "iso_unavailable"},
            )
            db.session.commit()
            return (
                jsonify(
                    errors={"iso": "ISO inaccessible sur le nœud sélectionné."}
                ),
                400,
            )

        allocation, reservation_error = _reserve_allocation(
            g.current_user.id, vm_request
        )
        if reservation_error:
            error_code, errors = reservation_error
            return jsonify(error=error_code, errors=errors), 409
        assert allocation is not None

        try:
            request_id = client.create_vm(vm_request.as_dict())
        except (PVETransportError, PVEProtocolError, PVEHTTPError):
            allocation.status = "failed"
            _add_audit(
                action="vm.create",
                target_type="vm",
                target_id=allocation.id,
                outcome="failure",
                actor_user_id=g.current_user.id,
                details={"reason": "pve_failure"},
            )
            db.session.commit()
            raise

        allocation.status = "accepted"
        allocation.upstream_request_id = request_id
        _add_audit(
            action="vm.create",
            target_type="vm",
            target_id=allocation.id,
            outcome="success",
            actor_user_id=g.current_user.id,
            details={"name": allocation.name},
        )
        db.session.commit()
        return jsonify(status="accepted", request_id=request_id), 202

    def _reserve_allocation(
        user_id: int, vm_request: VMRequest
    ) -> tuple[VMAllocation | None, tuple[str, dict[str, str]] | None]:
        user = db.session.scalar(
            select(User).where(User.id == user_id).with_for_update()
        )
        if user is None:  # pragma: no cover - protégé par login_required
            raise RuntimeError("Utilisateur de session introuvable.")
        usage = _quota_usage(user.id)
        requested = {
            "vms": 1,
            "cpu": vm_request.cpu,
            "ram_mb": vm_request.ram_mb,
            "disk_gb": vm_request.disk_gb,
        }
        limits = {
            "vms": user.quota_vms,
            "cpu": user.quota_cpu,
            "ram_mb": user.quota_ram_mb,
            "disk_gb": user.quota_disk_gb,
        }
        exceeded = {
            field: f"Quota dépassé ({usage[field]} + {requested[field]} > {limits[field]})."
            for field in requested
            if usage[field] + requested[field] > limits[field]
        }
        if exceeded:
            _add_audit(
                action="vm.create",
                target_type="vm",
                target_id=vm_request.name,
                outcome="denied",
                actor_user_id=user.id,
                details={"reason": "quota_exceeded", "fields": sorted(exceeded)},
            )
            db.session.commit()
            return None, ("quota_exceeded", exceeded)

        allocation = VMAllocation(owner_id=user.id, **vm_request.as_dict())
        db.session.add(allocation)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            _add_audit(
                action="vm.create",
                target_type="vm",
                target_id=vm_request.name,
                outcome="denied",
                actor_user_id=user.id,
                details={"reason": "name_conflict"},
            )
            db.session.commit()
            return None, (
                "name_conflict",
                {"name": "Ce nom de VM a déjà été utilisé pour ce compte."},
            )
        return allocation, None

    return app


def _quota_usage(user_id: int) -> dict[str, int]:
    row = db.session.execute(
        select(
            func.count(VMAllocation.id),
            func.coalesce(func.sum(VMAllocation.cpu), 0),
            func.coalesce(func.sum(VMAllocation.ram_mb), 0),
            func.coalesce(func.sum(VMAllocation.disk_gb), 0),
        ).where(
            VMAllocation.owner_id == user_id,
            VMAllocation.status.in_(ACTIVE_VM_STATUSES),
        )
    ).one()
    return {
        "vms": int(row[0]),
        "cpu": int(row[1]),
        "ram_mb": int(row[2]),
        "disk_gb": int(row[3]),
    }


def _add_audit(
    *,
    action: str,
    target_type: str,
    outcome: str,
    target_id: str | None = None,
    actor_user_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.session.add(
        AuditEvent(
            actor_user_id=actor_user_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            outcome=outcome,
            request_id=getattr(g, "request_id", str(uuid.uuid4())),
            details=details or {},
        )
    )


def _initialize_test_database(app: Flask) -> None:
    with app.app_context():
        db.create_all()
        username = app.config.get("PORTAL_ADMIN_USERNAME")
        password_hash = app.config.get("PORTAL_ADMIN_PASSWORD_HASH")
        if username and password_hash:
            db.session.add(
                User(
                    username=username,
                    password_hash=password_hash,
                    role="admin",
                    quota_vms=100,
                    quota_cpu=512,
                    quota_ram_mb=1048576,
                    quota_disk_gb=102400,
                )
            )
            db.session.commit()
