from __future__ import annotations

import os
import secrets
import socket
import time
import uuid
from datetime import timedelta
from functools import wraps
from hmac import compare_digest
from typing import Any

import click
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from flask import Flask, g, jsonify, request, session
from flask_migrate import Migrate
from requests import RequestException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash

from .config import environment_value
from .jobs import process_next_job
from .models import (
    ACTIVE_VM_STATUSES,
    AuditEvent,
    ImageProfile,
    ProvisioningJob,
    User,
    VMAllocation,
    db,
)
from .oidc import (
    OIDCIdentity,
    OIDCIdentityError,
    collision_safe_username,
    extract_oidc_identity,
)
from .password_pusher import PasswordPusherClient
from .pve import PVEClient, PVEHTTPError, PVEProtocolError, PVETransportError
from .validation import (
    ImageProfileCreateRequest,
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


def create_app(
    test_config: dict | None = None,
    *,
    pve_client=None,
    oidc_client=None,
    password_pusher_client=None,
) -> Flask:
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
        PORTAL_ADMIN_PASSWORD_HASH=environment_value("PORTAL_ADMIN_PASSWORD_HASH"),
        PORTAL_SESSION_SECRET=environment_value("PORTAL_SESSION_SECRET", strip=False),
        PORTAL_LOCAL_AUTH_ENABLED=_bool_environment(
            "PORTAL_LOCAL_AUTH_ENABLED", True
        ),
        PORTAL_OIDC_ISSUER=os.environ.get("PORTAL_OIDC_ISSUER", "").rstrip("/"),
        PORTAL_OIDC_CLIENT_ID=os.environ.get("PORTAL_OIDC_CLIENT_ID", "").strip(),
        PORTAL_OIDC_CLIENT_SECRET=environment_value("PORTAL_OIDC_CLIENT_SECRET"),
        PORTAL_OIDC_REDIRECT_URI=os.environ.get(
            "PORTAL_OIDC_REDIRECT_URI", ""
        ).strip(),
        PORTAL_OIDC_ROLE_ADMIN=os.environ.get(
            "PORTAL_OIDC_ROLE_ADMIN", "portal-admin"
        ).strip(),
        PORTAL_OIDC_ROLE_OPERATOR=os.environ.get(
            "PORTAL_OIDC_ROLE_OPERATOR", "portal-operator"
        ).strip(),
        PORTAL_OIDC_ROLE_USER=os.environ.get(
            "PORTAL_OIDC_ROLE_USER", "portal-user"
        ).strip(),
        PORTAL_OIDC_DEFAULT_QUOTA_VMS=int(
            os.environ.get("PORTAL_OIDC_DEFAULT_QUOTA_VMS", "3")
        ),
        PORTAL_OIDC_DEFAULT_QUOTA_CPU=int(
            os.environ.get("PORTAL_OIDC_DEFAULT_QUOTA_CPU", "8")
        ),
        PORTAL_OIDC_DEFAULT_QUOTA_RAM_MB=int(
            os.environ.get("PORTAL_OIDC_DEFAULT_QUOTA_RAM_MB", "16384")
        ),
        PORTAL_OIDC_DEFAULT_QUOTA_DISK_GB=int(
            os.environ.get("PORTAL_OIDC_DEFAULT_QUOTA_DISK_GB", "200")
        ),
        PORTAL_JOB_POLL_SECONDS=int(os.environ.get("PORTAL_JOB_POLL_SECONDS", "5")),
        PORTAL_JOB_LEASE_SECONDS=int(
            os.environ.get("PORTAL_JOB_LEASE_SECONDS", "300")
        ),
        PORTAL_PWPUSH_URL=os.environ.get("PORTAL_PWPUSH_URL", "").strip(),
        PORTAL_PWPUSH_API_TOKEN=environment_value("PORTAL_PWPUSH_API_TOKEN"),
        PORTAL_PWPUSH_CA_BUNDLE=os.environ.get(
            "PORTAL_PWPUSH_CA_BUNDLE", ""
        ).strip(),
        PORTAL_PWPUSH_EXPIRE_DAYS=int(
            os.environ.get("PORTAL_PWPUSH_EXPIRE_DAYS", "1")
        ),
        PORTAL_PWPUSH_EXPIRE_VIEWS=int(
            os.environ.get("PORTAL_PWPUSH_EXPIRE_VIEWS", "1")
        ),
        PORTAL_DUMMY_PASSWORD_HASH=generate_password_hash(
            secrets.token_urlsafe(32), method="scrypt"
        ),
        SQLALCHEMY_DATABASE_URI=environment_value(
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
    _validate_identity_configuration(app)
    _validate_job_configuration(app)
    password_pusher = _configure_password_pusher(app, password_pusher_client)

    db.init_app(app)
    Migrate(app, db)
    if app.config.get("TESTING"):
        _initialize_test_database(app)

    oidc = _configure_oidc(app, oidc_client)
    app.extensions["oidc_client"] = oidc
    app.extensions["password_pusher_client"] = password_pusher

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

    def establish_session(user: User, authentication: str) -> str:
        session.clear()
        session["user_id"] = user.id
        session["authentication"] = authentication
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return session["csrf_token"]

    @app.cli.command("bootstrap-admin")
    def bootstrap_admin_command():
        """Crée le premier administrateur après `flask db upgrade`."""
        if not app.config["PORTAL_LOCAL_AUTH_ENABLED"]:
            raise click.ClickException("L'authentification locale est désactivée.")
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

    @app.cli.command("worker")
    @click.option("--once", is_flag=True, help="Traite une seule étape puis quitte.")
    def worker_command(once: bool):
        """Exécute le worker de provisionnement PostgreSQL."""
        worker_id = f"{socket.gethostname()}:{os.getpid()}"
        while True:
            processed = process_next_job(
                client,
                password_pusher,
                worker_id=worker_id,
                poll_seconds=app.config["PORTAL_JOB_POLL_SECONDS"],
                lease_seconds=app.config["PORTAL_JOB_LEASE_SECONDS"],
            )
            if once:
                return
            if not processed:
                time.sleep(app.config["PORTAL_JOB_POLL_SECONDS"])

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
        if not app.config["PORTAL_LOCAL_AUTH_ENABLED"]:
            return jsonify(error="local_auth_disabled"), 403
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
            if user is not None and user.auth_provider == "local"
            else app.config["PORTAL_DUMMY_PASSWORD_HASH"]
        )
        password_valid = isinstance(password, str) and check_password_hash(
            password_hash, password
        )
        if (
            user is None
            or user.auth_provider != "local"
            or not user.is_active
            or not password_valid
        ):
            _add_audit(
                action="authentication.login",
                target_type="user",
                target_id=username if isinstance(username, str) else None,
                outcome="failure",
            )
            db.session.commit()
            return jsonify(error="invalid_credentials"), 401

        csrf_token = establish_session(user, "local")
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
            csrf_token=csrf_token,
            user=user.public_dict(),
        )

    @app.get("/auth/oidc/login")
    def oidc_login():
        if oidc is None:
            return jsonify(error="oidc_not_configured"), 404
        session.clear()
        session["oidc_nonce"] = secrets.token_urlsafe(32)
        try:
            return oidc.authorize_redirect(
                app.config["PORTAL_OIDC_REDIRECT_URI"],
                nonce=session["oidc_nonce"],
            )
        except (OAuthError, RequestException):
            session.clear()
            _add_audit(
                action="authentication.oidc_login",
                target_type="provider",
                target_id="oidc",
                outcome="failure",
                details={"reason": "provider_unavailable"},
            )
            db.session.commit()
            return jsonify(error="oidc_unavailable"), 503

    @app.get("/auth/oidc/callback")
    def oidc_callback():
        if oidc is None:
            return jsonify(error="oidc_not_configured"), 404
        if not session.pop("oidc_nonce", None):
            return jsonify(error="oidc_session_invalid"), 400
        try:
            token = oidc.authorize_access_token()
            claims = token.get("userinfo") if isinstance(token, dict) else None
            if not isinstance(claims, dict):
                raise OIDCIdentityError("Claims OIDC absents.")
            identity = extract_oidc_identity(
                claims,
                expected_issuer=app.config["PORTAL_OIDC_ISSUER"],
                client_id=app.config["PORTAL_OIDC_CLIENT_ID"],
                role_names={
                    "admin": app.config["PORTAL_OIDC_ROLE_ADMIN"],
                    "operator": app.config["PORTAL_OIDC_ROLE_OPERATOR"],
                    "user": app.config["PORTAL_OIDC_ROLE_USER"],
                },
            )
        except OAuthError:
            session.clear()
            _add_audit(
                action="authentication.oidc_login",
                target_type="user",
                outcome="failure",
                details={"reason": "protocol_failure"},
            )
            db.session.commit()
            return jsonify(error="oidc_authentication_failed"), 401
        except RequestException:
            session.clear()
            _add_audit(
                action="authentication.oidc_login",
                target_type="provider",
                target_id="oidc",
                outcome="failure",
                details={"reason": "provider_unavailable"},
            )
            db.session.commit()
            return jsonify(error="oidc_unavailable"), 503
        except OIDCIdentityError:
            session.clear()
            _add_audit(
                action="authentication.oidc_login",
                target_type="user",
                outcome="denied",
                details={"reason": "identity_rejected"},
            )
            db.session.commit()
            return jsonify(error="oidc_access_denied"), 403

        user = _find_or_create_oidc_user(app, identity)
        if not user.is_active:
            _add_audit(
                action="authentication.oidc_login",
                target_type="user",
                target_id=str(user.id),
                outcome="denied",
                details={"reason": "account_disabled"},
            )
            db.session.commit()
            session.clear()
            return jsonify(error="oidc_access_denied"), 403

        user.role = identity.role
        _add_audit(
            action="authentication.oidc_login",
            target_type="user",
            target_id=str(user.id),
            outcome="success",
            actor_user_id=user.id,
        )
        db.session.commit()
        csrf_token = establish_session(user, "oidc")
        return jsonify(
            status="authenticated", csrf_token=csrf_token, user=user.public_dict()
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

    @app.get("/api/image-profiles")
    @login_required
    def list_image_profiles():
        profiles = db.session.scalars(
            select(ImageProfile)
            .where(ImageProfile.enabled.is_(True))
            .order_by(ImageProfile.label)
        ).all()
        return jsonify(profiles=[profile.public_dict() for profile in profiles])

    @app.get("/api/admin/image-profiles")
    @login_required
    @role_required("admin")
    def admin_list_image_profiles():
        profiles = db.session.scalars(
            select(ImageProfile).order_by(ImageProfile.label)
        ).all()
        return jsonify(profiles=[profile.public_dict() for profile in profiles])

    @app.post("/api/admin/image-profiles")
    @login_required
    @role_required("admin")
    @csrf_protected
    def create_image_profile():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            profile_request = ImageProfileCreateRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400
        profile = ImageProfile(
            slug=profile_request.slug,
            label=profile_request.label,
            description=profile_request.description,
            source_type=profile_request.source_type,
            iso=profile_request.iso,
            template_node=profile_request.template_node,
            template_vmid=profile_request.template_vmid,
            created_by_id=g.current_user.id,
        )
        db.session.add(profile)
        try:
            db.session.flush()
        except IntegrityError:
            db.session.rollback()
            return jsonify(errors={"slug": "Identifiant déjà utilisé."}), 409
        _add_audit(
            action="image_profile.create",
            target_type="image_profile",
            target_id=profile.slug,
            outcome="success",
            actor_user_id=g.current_user.id,
        )
        db.session.commit()
        return jsonify(profile=profile.public_dict()), 201

    @app.patch("/api/admin/image-profiles/<slug>")
    @login_required
    @role_required("admin")
    @csrf_protected
    def update_image_profile(slug: str):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"enabled"} or type(payload.get("enabled")) is not bool:
            return jsonify(errors={"enabled": "Booléen requis."}), 400
        profile = db.session.scalar(
            select(ImageProfile).where(ImageProfile.slug == slug)
        )
        if profile is None:
            return jsonify(error="not_found"), 404
        profile.enabled = payload["enabled"]
        _add_audit(
            action="image_profile.update",
            target_type="image_profile",
            target_id=profile.slug,
            outcome="success",
            actor_user_id=g.current_user.id,
            details={"enabled": profile.enabled},
        )
        db.session.commit()
        return jsonify(profile=profile.public_dict())

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

    @app.get("/api/jobs/<job_id>")
    @login_required
    def get_job(job_id: str):
        job = db.session.get(ProvisioningJob, job_id)
        if job is None:
            return jsonify(error="not_found"), 404
        if job.allocation.owner_id != g.current_user.id and g.current_user.role not in {
            "admin",
            "operator",
        }:
            return jsonify(error="forbidden"), 403
        return jsonify(
            job=job.public_dict(
                include_credentials=job.allocation.owner_id == g.current_user.id
            )
        )

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

        profile = db.session.scalar(
            select(ImageProfile).where(
                ImageProfile.slug == vm_request.profile,
                ImageProfile.enabled.is_(True),
            )
        )
        if profile is None:
            return jsonify(errors={"profile": "Profil indisponible."}), 400
        if profile.source_type == "cloud_init" and not vm_request.guest_username:
            return (
                jsonify(
                    errors={
                        "guest_username": "Identifiant Linux requis pour ce profil."
                    }
                ),
                400,
            )
        if profile.source_type == "iso" and vm_request.guest_username:
            return (
                jsonify(
                    errors={
                        "guest_username": "Ce profil ISO ne prend pas en charge cloud-init."
                    }
                ),
                400,
            )
        if profile.source_type == "cloud_init" and password_pusher is None:
            return jsonify(error="password_pusher_unavailable"), 503

        allocation, job, reservation_error = _reserve_allocation(
            g.current_user.id, vm_request, profile
        )
        if reservation_error:
            error_code, errors = reservation_error
            return jsonify(error=error_code, errors=errors), 409
        assert allocation is not None and job is not None
        _add_audit(
            action="vm.enqueue",
            target_type="vm",
            target_id=allocation.id,
            outcome="success",
            actor_user_id=g.current_user.id,
            details={"job_id": job.id, "profile": profile.slug},
        )
        db.session.commit()
        return jsonify(status="queued", job_id=job.id, vm_id=allocation.id), 202

    def _reserve_allocation(
        user_id: int, vm_request: VMRequest, profile: ImageProfile
    ) -> tuple[
        VMAllocation | None,
        ProvisioningJob | None,
        tuple[str, dict[str, str]] | None,
    ]:
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
            return None, None, ("quota_exceeded", exceeded)

        allocation = VMAllocation(
            owner_id=user.id,
            profile_id=profile.id,
            name=vm_request.name,
            node=vm_request.node,
            iso=profile.iso,
            guest_username=vm_request.guest_username,
            cpu=vm_request.cpu,
            ram_mb=vm_request.ram_mb,
            disk_gb=vm_request.disk_gb,
            status="queued",
        )
        job = ProvisioningJob(allocation=allocation)
        db.session.add(allocation)
        db.session.add(job)
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
            return None, None, (
                "name_conflict",
                {"name": "Ce nom de VM a déjà été utilisé pour ce compte."},
            )
        return allocation, job, None

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


def _validate_identity_configuration(app: Flask) -> None:
    oidc_keys = (
        "PORTAL_OIDC_ISSUER",
        "PORTAL_OIDC_CLIENT_ID",
        "PORTAL_OIDC_CLIENT_SECRET",
        "PORTAL_OIDC_REDIRECT_URI",
    )
    configured = [bool(app.config.get(key)) for key in oidc_keys]
    if any(configured) and not all(configured):
        missing = [key for key in oidc_keys if not app.config.get(key)]
        raise ValueError("Configuration OIDC incomplète: " + ", ".join(missing))
    app.config["PORTAL_OIDC_ENABLED"] = all(configured)
    if not app.config["PORTAL_LOCAL_AUTH_ENABLED"] and not app.config["PORTAL_OIDC_ENABLED"]:
        raise ValueError("Au moins un mode d'authentification doit être activé.")
    if not app.config["PORTAL_OIDC_ENABLED"]:
        return
    if not app.config.get("TESTING"):
        for key in ("PORTAL_OIDC_ISSUER", "PORTAL_OIDC_REDIRECT_URI"):
            if not app.config[key].startswith("https://"):
                raise ValueError(f"{key} doit utiliser HTTPS.")
    role_names = {
        app.config["PORTAL_OIDC_ROLE_ADMIN"],
        app.config["PORTAL_OIDC_ROLE_OPERATOR"],
        app.config["PORTAL_OIDC_ROLE_USER"],
    }
    if "" in role_names or len(role_names) != 3:
        raise ValueError("Les trois rôles OIDC doivent être distincts et non vides.")
    for key, maximum in (
        ("PORTAL_OIDC_DEFAULT_QUOTA_VMS", 100),
        ("PORTAL_OIDC_DEFAULT_QUOTA_CPU", 512),
        ("PORTAL_OIDC_DEFAULT_QUOTA_RAM_MB", 1048576),
        ("PORTAL_OIDC_DEFAULT_QUOTA_DISK_GB", 102400),
    ):
        value = app.config[key]
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError(f"{key} est invalide.")


def _validate_job_configuration(app: Flask) -> None:
    for key, maximum in (
        ("PORTAL_JOB_POLL_SECONDS", 300),
        ("PORTAL_JOB_LEASE_SECONDS", 3600),
    ):
        value = app.config[key]
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{key} est invalide.")


def _configure_password_pusher(app: Flask, injected_client):
    if injected_client is not None:
        return injected_client
    url = app.config["PORTAL_PWPUSH_URL"]
    token = app.config["PORTAL_PWPUSH_API_TOKEN"]
    if not url and not token:
        return None
    if not url or not token:
        raise ValueError(
            "PORTAL_PWPUSH_URL et PORTAL_PWPUSH_API_TOKEN doivent être configurés ensemble."
        )
    return PasswordPusherClient(
        base_url=url,
        api_token=token,
        expire_after_days=app.config["PORTAL_PWPUSH_EXPIRE_DAYS"],
        expire_after_views=app.config["PORTAL_PWPUSH_EXPIRE_VIEWS"],
        ca_bundle=app.config["PORTAL_PWPUSH_CA_BUNDLE"] or None,
    )


def _configure_oidc(app: Flask, injected_client):
    if not app.config["PORTAL_OIDC_ENABLED"]:
        return None
    if injected_client is not None:
        return injected_client
    oauth = OAuth(app)
    return oauth.register(
        name="keycloak",
        client_id=app.config["PORTAL_OIDC_CLIENT_ID"],
        client_secret=app.config["PORTAL_OIDC_CLIENT_SECRET"],
        server_metadata_url=(
            app.config["PORTAL_OIDC_ISSUER"] + "/.well-known/openid-configuration"
        ),
        client_kwargs={
            "scope": "openid profile email",
            "code_challenge_method": "S256",
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )


def _find_or_create_oidc_user(app: Flask, identity: OIDCIdentity) -> User:
    user = db.session.scalar(
        select(User).where(
            User.external_issuer == identity.issuer,
            User.external_subject == identity.subject,
        )
    )
    if user is not None:
        return user

    username = identity.username
    if db.session.scalar(select(User.id).where(User.username == username)) is not None:
        username = collision_safe_username(
            identity.username, identity.issuer, identity.subject
        )
    user = User(
        username=username,
        password_hash=None,
        auth_provider="oidc",
        external_issuer=identity.issuer,
        external_subject=identity.subject,
        role=identity.role,
        quota_vms=app.config["PORTAL_OIDC_DEFAULT_QUOTA_VMS"],
        quota_cpu=app.config["PORTAL_OIDC_DEFAULT_QUOTA_CPU"],
        quota_ram_mb=app.config["PORTAL_OIDC_DEFAULT_QUOTA_RAM_MB"],
        quota_disk_gb=app.config["PORTAL_OIDC_DEFAULT_QUOTA_DISK_GB"],
    )
    db.session.add(user)
    db.session.flush()
    return user


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
        db.session.add(
            ImageProfile(
                slug="debian-12",
                label="Debian 12",
                description="Profil de test",
                source_type="iso",
                iso="local:iso/debian-12.iso",
            )
        )
        db.session.commit()
