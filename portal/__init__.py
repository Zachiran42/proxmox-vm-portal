from __future__ import annotations

import csv
import json
import os
import secrets
import socket
import time
import uuid
from datetime import UTC, datetime, timedelta
from functools import wraps
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from io import StringIO
from typing import Any

import click
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from flask import (
    Flask,
    Response,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_migrate import Migrate
from requests import RequestException
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix
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
    VMOperation,
    WorkerHeartbeat,
    db,
)
from .observability import render_prometheus_metrics
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
    IncidentActionRequest,
    UserCreateRequest,
    UserUpdateRequest,
    ValidationError,
    VMActionRequest,
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
        PORTAL_METRICS_TOKEN=environment_value("PORTAL_METRICS_TOKEN"),
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
        PORTAL_LOGIN_MAX_FAILURES=int(
            os.environ.get("PORTAL_LOGIN_MAX_FAILURES", "5")
        ),
        PORTAL_LOGIN_IP_MAX_FAILURES=int(
            os.environ.get("PORTAL_LOGIN_IP_MAX_FAILURES", "25")
        ),
        PORTAL_LOGIN_WINDOW_SECONDS=int(
            os.environ.get("PORTAL_LOGIN_WINDOW_SECONDS", "900")
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

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # type: ignore[method-assign]

    if not app.config.get("PORTAL_SESSION_SECRET"):
        raise ValueError(
            "Variable d'environnement d'authentification manquante: "
            "PORTAL_SESSION_SECRET"
        )
    app.secret_key = app.config["PORTAL_SESSION_SECRET"]
    _validate_identity_configuration(app)
    _validate_job_configuration(app)
    _validate_login_throttle_configuration(app)
    _validate_observability_configuration(app)
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
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
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
            if user.must_change_password and request.endpoint not in {
                "me",
                "change_own_password",
                "logout",
            }:
                return jsonify(error="password_change_required"), 403
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
                must_change_password=True,
                quota_vms=100,
                quota_cpu=512,
                quota_ram_mb=1048576,
                quota_disk_gb=102400,
            )
        )
        db.session.commit()
        click.echo(f"Administrateur {username!r} créé.")

    @app.cli.command("reset-admin-password")
    @click.option(
        "--username",
        default=None,
        help="Administrateur local à réinitialiser (admin configuré par défaut).",
    )
    @click.option(
        "--password",
        prompt="Nouveau mot de passe administrateur",
        confirmation_prompt="Confirmation",
        hide_input=True,
    )
    def reset_admin_password_command(username: str | None, password: str):
        """Réinitialise localement un administrateur sans modifier les autres comptes."""
        if not app.config["PORTAL_LOCAL_AUTH_ENABLED"]:
            raise click.ClickException("L'authentification locale est désactivée.")
        if not 1 <= len(password) <= 256:
            raise click.ClickException(
                "Le mot de passe doit contenir entre 1 et 256 caractères."
            )

        selected_username = username or app.config["PORTAL_ADMIN_USERNAME"]
        user = db.session.scalar(
            select(User).where(User.username == selected_username)
        )
        if user is None:
            raise click.ClickException(
                f"Le compte {selected_username!r} est introuvable."
            )
        if user.role != "admin":
            raise click.ClickException(
                f"Le compte {selected_username!r} n'est pas administrateur."
            )
        if user.auth_provider != "local":
            raise click.ClickException(
                f"Le compte {selected_username!r} est géré par une identité externe."
            )

        user.password_hash = generate_password_hash(password, method="scrypt")
        user.must_change_password = False
        db.session.commit()
        click.echo(f"Mot de passe de l'administrateur {selected_username!r} modifié.")

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

    @app.cli.command("check-proxmox")
    def check_proxmox_command():
        """Valide TLS, le token et la permission de lecture du cluster."""
        try:
            nodes = client.list_nodes()
        except PVEHTTPError as error:
            if error.status == 401:
                raise click.ClickException(
                    "Token Proxmox refusé (identifiant ou secret invalide)."
                ) from error
            if error.status == 403:
                raise click.ClickException(
                    "Token Proxmox reconnu mais permission Sys.Audit absente."
                ) from error
            raise click.ClickException(
                f"Proxmox a retourné l'erreur HTTP {error.status}."
            ) from error
        except PVETransportError as error:
            raise click.ClickException(
                "Connexion TLS à Proxmox impossible; vérifiez l'URL et la CA."
            ) from error
        except PVEProtocolError as error:
            raise click.ClickException("Réponse Proxmox invalide.") from error
        click.echo(
            "Connexion Proxmox validée; nœuds visibles: "
            + (", ".join(nodes) if nodes else "aucun")
        )

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/metrics")
    def metrics():
        expected = app.config["PORTAL_METRICS_TOKEN"]
        if not expected:
            return jsonify(error="not_found"), 404
        authorization = request.headers.get("Authorization", "")
        supplied = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not supplied or not compare_digest(expected, supplied):
            response = jsonify(error="metrics_authentication_required")
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "Bearer"
            return response
        return Response(
            render_prometheus_metrics(client),
            content_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/")
    def home():
        return render_template(
            "index.html",
            local_auth_enabled=app.config["PORTAL_LOCAL_AUTH_ENABLED"],
            oidc_enabled=oidc is not None,
        )

    @app.post("/login")
    def login():
        if not app.config["PORTAL_LOCAL_AUTH_ENABLED"]:
            return jsonify(error="local_auth_disabled"), 403
        credentials = request.get_json(silent=True)
        username = credentials.get("username") if isinstance(credentials, dict) else None
        password = credentials.get("password") if isinstance(credentials, dict) else None
        throttle_key, ip_key = _login_throttle_keys(
            app, username if isinstance(username, str) else ""
        )
        if _login_is_throttled(app, throttle_key, ip_key):
            _add_audit(
                action="authentication.throttled",
                target_type="login",
                target_id=throttle_key,
                outcome="denied",
            )
            db.session.commit()
            response = jsonify(error="too_many_attempts")
            response.headers["Retry-After"] = str(
                app.config["PORTAL_LOGIN_WINDOW_SECONDS"]
            )
            return response, 429
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
                target_type="login",
                target_id=throttle_key,
                outcome="failure",
            )
            _add_audit(
                action="authentication.login_ip",
                target_type="login_ip",
                target_id=ip_key,
                outcome="failure",
            )
            db.session.commit()
            return jsonify(error="invalid_credentials"), 401

        csrf_token = establish_session(user, "local")
        _add_audit(
            action="authentication.login",
            target_type="login",
            target_id=throttle_key,
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
        if request.accept_mimetypes.accept_html and not request.accept_mimetypes.accept_json:
            return redirect(url_for("home"))
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
        return jsonify(
            user=g.current_user.public_dict(),
            usage=_quota_usage(g.current_user.id),
            csrf_token=session["csrf_token"],
        )

    @app.post("/api/me/password")
    @login_required
    @csrf_protected
    def change_own_password():
        if g.current_user.auth_provider != "local":
            return jsonify(error="external_identity_managed"), 409
        payload = request.get_json(silent=True)
        password = payload.get("password") if isinstance(payload, dict) else None
        if not isinstance(password, str) or not 1 <= len(password) <= 256:
            return jsonify(
                errors={
                    "password": (
                        "Le mot de passe doit contenir entre 1 et 256 caractères."
                    )
                }
            ), 400
        if check_password_hash(g.current_user.password_hash, password):
            return jsonify(error="password_reuse"), 400

        g.current_user.password_hash = generate_password_hash(
            password, method="scrypt"
        )
        g.current_user.must_change_password = False
        _add_audit(
            action="user.password_change",
            target_type="user",
            target_id=str(g.current_user.id),
            outcome="success",
            actor_user_id=g.current_user.id,
        )
        db.session.commit()
        return jsonify(status="password_changed", user=g.current_user.public_dict())

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
        if (
            profile_request.source_type == "cloud_init"
            and profile_request.template_node is not None
            and profile_request.template_vmid is not None
            and not client.is_template_available(
                profile_request.template_node, profile_request.template_vmid
            )
        ):
            return jsonify(errors={"template": "Template Proxmox indisponible ou non converti."}), 422
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
        return jsonify(
            users=[
                {**user.public_dict(), "usage": _quota_usage(user.id)}
                for user in users
            ]
        )

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

    @app.patch("/api/admin/users/<int:user_id>")
    @login_required
    @role_required("admin")
    @csrf_protected
    def update_user(user_id: int):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            user_request = UserUpdateRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400
        user = db.session.get(User, user_id)
        if user is None:
            return jsonify(error="not_found"), 404
        if user.id == g.current_user.id and (
            not user_request.is_active or user_request.role != "admin"
        ):
            return jsonify(error="self_admin_protection"), 409
        if user.auth_provider == "oidc" and (
            user_request.role != user.role or user_request.password is not None
        ):
            return jsonify(error="external_identity_managed"), 409
        removes_active_admin = user.is_active and user.role == "admin" and (
            not user_request.is_active or user_request.role != "admin"
        )
        if removes_active_admin:
            active_admins = db.session.scalar(
                select(func.count(User.id)).where(
                    User.role == "admin", User.is_active.is_(True)
                )
            )
            if active_admins is None or active_admins <= 1:
                return jsonify(error="last_admin_protection"), 409

        old_role = user.role
        old_active = user.is_active
        user.role = user_request.role
        user.is_active = user_request.is_active
        user.quota_vms = user_request.quota_vms
        user.quota_cpu = user_request.quota_cpu
        user.quota_ram_mb = user_request.quota_ram_mb
        user.quota_disk_gb = user_request.quota_disk_gb
        if user_request.password is not None:
            user.password_hash = generate_password_hash(
                user_request.password, method="scrypt"
            )
        _add_audit(
            action="user.update",
            target_type="user",
            target_id=str(user.id),
            outcome="success",
            actor_user_id=g.current_user.id,
            details={
                "role_before": old_role,
                "role_after": user.role,
                "active_before": old_active,
                "active_after": user.is_active,
                "password_rotated": user_request.password is not None,
            },
        )
        db.session.commit()
        return jsonify(user=user.public_dict())

    @app.get("/api/admin/audit-events")
    @login_required
    @role_required("admin")
    def list_audit_events():
        events = db.session.scalars(
            select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100)
        ).all()
        return jsonify(events=[event.public_dict() for event in events])

    @app.get("/api/admin/audit-events.csv")
    @login_required
    @role_required("admin")
    def export_audit_events():
        raw_limit = request.args.get("limit", "1000")
        try:
            limit = int(raw_limit)
        except ValueError:
            return jsonify(errors={"limit": "Entier requis."}), 400
        if not 1 <= limit <= 5000:
            return jsonify(errors={"limit": "Valeur requise entre 1 et 5000."}), 400
        events = db.session.scalars(
            select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
        ).all()
        output = StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(
            (
                "created_at",
                "action",
                "outcome",
                "actor_user_id",
                "target_type",
                "target_id",
                "request_id",
                "details",
            )
        )
        for event in events:
            writer.writerow(
                _csv_safe_cell(value)
                for value in (
                    event.created_at.isoformat(),
                    event.action,
                    event.outcome,
                    event.actor_user_id,
                    event.target_type,
                    event.target_id,
                    event.request_id,
                    json.dumps(event.details, ensure_ascii=False, sort_keys=True),
                )
            )
        return Response(
            output.getvalue(),
            content_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="portal-audit.csv"'
            },
        )

    @app.get("/api/admin/operations")
    @login_required
    @role_required("admin")
    def operations_overview():
        now = datetime.now(UTC)
        heartbeat = db.session.scalar(
            select(WorkerHeartbeat)
            .order_by(WorkerHeartbeat.last_seen_at.desc())
            .limit(1)
        )
        if heartbeat is None:
            worker_service = {"status": "unknown", "last_seen_at": None}
        else:
            last_seen = heartbeat.last_seen_at
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=UTC)
            age_seconds = max(0, int((now - last_seen).total_seconds()))
            worker_service = {
                "status": "healthy"
                if age_seconds <= max(15, app.config["PORTAL_JOB_POLL_SECONDS"] * 3)
                else "degraded",
                "last_seen_at": last_seen.isoformat(),
                "age_seconds": age_seconds,
            }

        pve_started = time.monotonic()
        try:
            nodes = client.list_nodes()
            pve_service = {
                "status": "healthy" if nodes else "degraded",
                "online_nodes": len(nodes),
                "latency_ms": int((time.monotonic() - pve_started) * 1000),
            }
        except (PVETransportError, PVEHTTPError, PVEProtocolError):
            pve_service = {
                "status": "unavailable",
                "online_nodes": 0,
                "latency_ms": int((time.monotonic() - pve_started) * 1000),
            }

        provisioning_incidents = db.session.scalars(
            select(ProvisioningJob)
            .where(ProvisioningJob.status == "attention")
            .order_by(ProvisioningJob.updated_at.desc())
            .limit(25)
        ).all()
        lifecycle_incidents = db.session.scalars(
            select(VMOperation)
            .where(VMOperation.status == "attention")
            .order_by(VMOperation.updated_at.desc())
            .limit(25)
        ).all()
        incidents = [
            {
                "kind": "provisioning",
                "id": job.id,
                "error_code": job.error_code,
                "stage": job.stage,
                "action": "provision",
                "updated_at": job.updated_at.isoformat(),
                "can_resume": bool(
                    job.upstream_node and job.allocation.upstream_request_id
                ),
                "vm": {
                    "id": job.allocation_id,
                    "name": job.allocation.name,
                    "node": job.allocation.node,
                    "vmid": job.allocation.vmid,
                    "owner": job.allocation.owner.username,
                },
            }
            for job in provisioning_incidents
        ] + [
            {
                "kind": "lifecycle",
                "id": operation.id,
                "error_code": operation.error_code,
                "stage": None,
                "action": operation.action,
                "updated_at": operation.updated_at.isoformat(),
                "can_resume": bool(
                    operation.upstream_node and operation.upstream_request_id
                ),
                "vm": {
                    "id": operation.allocation_id,
                    "name": operation.allocation.name,
                    "node": operation.allocation.node,
                    "vmid": operation.allocation.vmid,
                    "owner": operation.allocation.owner.username,
                },
            }
            for operation in lifecycle_incidents
        ]
        incidents.sort(key=lambda incident: incident["updated_at"], reverse=True)

        provisioning_active = db.session.scalar(
            select(func.count(ProvisioningJob.id)).where(
                ProvisioningJob.status.in_(
                    ("queued", "validating", "submitting", "submitted", "polling")
                )
            )
        )
        lifecycle_active = db.session.scalar(
            select(func.count(VMOperation.id)).where(
                VMOperation.status.in_(
                    ("queued", "submitting", "submitted", "polling")
                )
            )
        )
        return jsonify(
            services={
                "database": {"status": "healthy"},
                "worker": worker_service,
                "proxmox": pve_service,
                "password_pusher": {
                    "status": "configured"
                    if password_pusher is not None
                    else "disabled"
                },
            },
            queue={
                "active": int(provisioning_active or 0)
                + int(lifecycle_active or 0),
                "attention": len(incidents),
            },
            incidents=incidents[:50],
            checked_at=now.isoformat(),
        )

    @app.post("/api/admin/incidents/<kind>/<incident_id>/actions")
    @login_required
    @role_required("admin")
    @csrf_protected
    def resolve_incident(kind: str, incident_id: str):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            incident_request = IncidentActionRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400

        if kind == "provisioning":
            incident = db.session.scalar(
                select(ProvisioningJob)
                .where(ProvisioningJob.id == incident_id)
                .with_for_update()
            )
            allocation = incident.allocation if incident is not None else None
            upstream_node = incident.upstream_node if incident is not None else None
            upstream_request_id = (
                allocation.upstream_request_id if allocation is not None else None
            )
        elif kind == "lifecycle":
            incident = db.session.scalar(
                select(VMOperation)
                .where(VMOperation.id == incident_id)
                .with_for_update()
            )
            allocation = incident.allocation if incident is not None else None
            upstream_node = incident.upstream_node if incident is not None else None
            upstream_request_id = (
                incident.upstream_request_id if incident is not None else None
            )
        else:
            return jsonify(error="not_found"), 404

        if incident is None or allocation is None:
            return jsonify(error="not_found"), 404
        if incident.status != "attention":
            return jsonify(error="incident_not_open"), 409
        previous_error = incident.error_code
        if incident_request.action == "resume_tracking":
            if not upstream_node or not upstream_request_id:
                return jsonify(error="incident_not_resumable"), 409
            incident.status = "submitted"
            incident.available_at = datetime.now(UTC)
            incident.completed_at = None
            incident.error_code = None
            incident.locked_at = None
            incident.locked_by = None
        else:
            if not compare_digest(
                incident_request.confirm_name or "", allocation.name
            ):
                return jsonify(error="confirmation_mismatch"), 409
            incident.status = "failed"
            incident.completed_at = datetime.now(UTC)
            incident.locked_at = None
            incident.locked_by = None
            if kind == "provisioning":
                allocation.status = "failed"

        _add_audit(
            action=f"incident.{incident_request.action}",
            target_type=kind,
            target_id=incident_id,
            outcome="success",
            actor_user_id=g.current_user.id,
            details={
                "vm_id": allocation.id,
                "previous_error": previous_error,
            },
        )
        db.session.commit()
        return jsonify(status=incident.status)

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

    @app.get("/api/jobs")
    @login_required
    def list_jobs():
        jobs = db.session.scalars(
            select(ProvisioningJob)
            .join(ProvisioningJob.allocation)
            .where(VMAllocation.owner_id == g.current_user.id)
            .order_by(ProvisioningJob.created_at.desc())
            .limit(25)
        ).all()
        return jsonify(
            jobs=[job.public_dict(include_credentials=True) for job in jobs]
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
        if allocation is None or job is None:  # pragma: no cover - invariant interne
            raise RuntimeError("Réservation de VM incohérente.")
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

    @app.post("/api/vms/<vm_id>/actions")
    @login_required
    @csrf_protected
    def request_vm_action(vm_id: str):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            action_request = VMActionRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400

        allocation = db.session.scalar(
            select(VMAllocation)
            .where(VMAllocation.id == vm_id)
            .with_for_update()
        )
        if allocation is None or allocation.owner_id != g.current_user.id:
            _add_audit(
                action="vm.lifecycle",
                target_type="vm",
                target_id=vm_id,
                outcome="denied",
                actor_user_id=g.current_user.id,
                details={"reason": "not_found_or_not_owner"},
            )
            db.session.commit()
            return jsonify(error="not_found"), 404
        if allocation.vmid is None:
            return jsonify(error="vm_not_ready"), 409
        if (
            action_request.action == "delete"
            and not compare_digest(action_request.confirm_name or "", allocation.name)
        ):
            return jsonify(error="confirmation_mismatch"), 409

        allowed_states = {
            "start": {"accepted", "stopped"},
            "stop": {"accepted", "running"},
            "reboot": {"running"},
            "delete": {"accepted", "stopped"},
        }
        if allocation.status not in allowed_states[action_request.action]:
            return jsonify(error="lifecycle_invalid_state"), 409
        active_operation = db.session.scalar(
            select(VMOperation.id).where(
                VMOperation.allocation_id == allocation.id,
                VMOperation.status.in_(
                    ("queued", "submitting", "submitted", "polling")
                ),
            )
        )
        if active_operation is not None:
            return jsonify(error="operation_in_progress"), 409

        operation = VMOperation(
            allocation_id=allocation.id,
            actor_user_id=g.current_user.id,
            action=action_request.action,
        )
        db.session.add(operation)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify(error="operation_in_progress"), 409
        return jsonify(operation=operation.public_dict()), 202

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


def _csv_safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


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


def _validate_login_throttle_configuration(app: Flask) -> None:
    for key, minimum, maximum in (
        ("PORTAL_LOGIN_MAX_FAILURES", 1, 20),
        ("PORTAL_LOGIN_IP_MAX_FAILURES", 1, 200),
        ("PORTAL_LOGIN_WINDOW_SECONDS", 60, 86400),
    ):
        value = app.config[key]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"{key} est invalide.")
    if (
        app.config["PORTAL_LOGIN_IP_MAX_FAILURES"]
        < app.config["PORTAL_LOGIN_MAX_FAILURES"]
    ):
        raise ValueError(
            "PORTAL_LOGIN_IP_MAX_FAILURES doit être supérieur ou égal au seuil par compte."
        )


def _validate_observability_configuration(app: Flask) -> None:
    token = app.config["PORTAL_METRICS_TOKEN"]
    if token and len(token) < 32:
        raise ValueError("PORTAL_METRICS_TOKEN doit contenir au moins 32 caractères.")


def _login_throttle_keys(app: Flask, username: str) -> tuple[str, str]:
    remote_addr = request.remote_addr or "unknown"
    secret = app.config["PORTAL_SESSION_SECRET"].encode("utf-8")

    def digest(value: str) -> str:
        return hmac_new(secret, value.encode("utf-8"), sha256).hexdigest()

    normalized_username = username[:128].casefold()
    return (
        digest(f"account-ip\0{normalized_username}\0{remote_addr}"),
        digest(f"ip\0{remote_addr}"),
    )


def _login_is_throttled(app: Flask, throttle_key: str, ip_key: str) -> bool:
    cutoff = datetime.now(UTC) - timedelta(
        seconds=app.config["PORTAL_LOGIN_WINDOW_SECONDS"]
    )
    last_success = db.session.scalar(
        select(func.max(AuditEvent.created_at)).where(
            AuditEvent.action == "authentication.login",
            AuditEvent.target_id == throttle_key,
            AuditEvent.outcome == "success",
        )
    )
    if last_success is not None and last_success.tzinfo is None:
        last_success = last_success.replace(tzinfo=UTC)
    account_cutoff = max(cutoff, last_success) if last_success else cutoff
    account_failures = db.session.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.action == "authentication.login",
            AuditEvent.target_id == throttle_key,
            AuditEvent.outcome == "failure",
            AuditEvent.created_at >= account_cutoff,
        )
    )
    ip_failures = db.session.scalar(
        select(func.count(AuditEvent.id)).where(
            AuditEvent.action == "authentication.login_ip",
            AuditEvent.target_id == ip_key,
            AuditEvent.outcome == "failure",
            AuditEvent.created_at >= cutoff,
        )
    )
    return (
        int(account_failures or 0) >= app.config["PORTAL_LOGIN_MAX_FAILURES"]
        or int(ip_failures or 0) >= app.config["PORTAL_LOGIN_IP_MAX_FAILURES"]
    )


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
            "token_endpoint_auth_method": "client_secret_basic",  # nosec B105
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
