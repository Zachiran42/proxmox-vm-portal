from __future__ import annotations

import csv
import json
import os
import secrets
import socket
import time
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import wraps
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from io import StringIO
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Any

import click
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from cryptography import x509
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
from .guest_secrets import encrypt_guest_password
from .integration_secrets import (
    IntegrationSecretError,
    decrypt_integration_secret,
    encrypt_integration_secret,
)
from .jobs import process_next_job
from .ldap_auth import (
    LDAPAccessDenied,
    LDAPClient,
    LDAPConfigurationError,
    LDAPIdentity,
    LDAPUnavailable,
)
from .models import (
    ACTIVE_VM_STATUSES,
    AuditEvent,
    ImageProfile,
    NetBoxConfiguration,
    NetworkProfile,
    PortalSetting,
    ProvisioningJob,
    ProxmoxConfiguration,
    User,
    VMAllocation,
    VMOperation,
    WorkerHeartbeat,
    db,
)
from .netbox import NetBoxClient, NetBoxUnavailable
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
    NetBoxConfigurationRequest,
    NetworkProfileRequest,
    ProxmoxConfigurationRequest,
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
    ldap_client=None,
    password_pusher_client=None,
    netbox_client=None,
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
        PORTAL_LDAP_URI=os.environ.get("PORTAL_LDAP_URI", "").strip(),
        PORTAL_LDAP_BIND_DN=os.environ.get("PORTAL_LDAP_BIND_DN", "").strip(),
        PORTAL_LDAP_BIND_PASSWORD=environment_value("PORTAL_LDAP_BIND_PASSWORD"),
        PORTAL_LDAP_BASE_DN=os.environ.get("PORTAL_LDAP_BASE_DN", "").strip(),
        PORTAL_LDAP_USER_FILTER=os.environ.get(
            "PORTAL_LDAP_USER_FILTER", "(sAMAccountName={username})"
        ).strip(),
        PORTAL_LDAP_USERNAME_ATTRIBUTE=os.environ.get(
            "PORTAL_LDAP_USERNAME_ATTRIBUTE", "sAMAccountName"
        ).strip(),
        PORTAL_LDAP_GROUP_ATTRIBUTE=os.environ.get(
            "PORTAL_LDAP_GROUP_ATTRIBUTE", "memberOf"
        ).strip(),
        PORTAL_LDAP_GROUP_ADMIN=os.environ.get("PORTAL_LDAP_GROUP_ADMIN", "").strip(),
        PORTAL_LDAP_GROUP_OPERATOR=os.environ.get(
            "PORTAL_LDAP_GROUP_OPERATOR", ""
        ).strip(),
        PORTAL_LDAP_GROUP_USER=os.environ.get("PORTAL_LDAP_GROUP_USER", "").strip(),
        PORTAL_LDAP_CA_FILE=os.environ.get("PORTAL_LDAP_CA_FILE", "").strip(),
        PORTAL_LDAP_START_TLS=_bool_environment("PORTAL_LDAP_START_TLS", True),
        PORTAL_LDAP_DEFAULT_QUOTA_VMS=int(
            os.environ.get("PORTAL_LDAP_DEFAULT_QUOTA_VMS", "3")
        ),
        PORTAL_LDAP_DEFAULT_QUOTA_CPU=int(
            os.environ.get("PORTAL_LDAP_DEFAULT_QUOTA_CPU", "8")
        ),
        PORTAL_LDAP_DEFAULT_QUOTA_RAM_MB=int(
            os.environ.get("PORTAL_LDAP_DEFAULT_QUOTA_RAM_MB", "16384")
        ),
        PORTAL_LDAP_DEFAULT_QUOTA_DISK_GB=int(
            os.environ.get("PORTAL_LDAP_DEFAULT_QUOTA_DISK_GB", "200")
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
        PORTAL_NETBOX_URL=os.environ.get("PORTAL_NETBOX_URL", "").strip(),
        PORTAL_NETBOX_API_TOKEN=environment_value("PORTAL_NETBOX_API_TOKEN"),
        PORTAL_NETBOX_CA_BUNDLE=os.environ.get(
            "PORTAL_NETBOX_CA_BUNDLE", ""
        ).strip(),
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
    netbox_environment = _configure_netbox(app, netbox_client)

    db.init_app(app)
    Migrate(app, db)
    if app.config.get("TESTING"):
        _initialize_test_database(app)

    oidc = _configure_oidc(app, oidc_client)
    ldap = _configure_ldap(app, ldap_client)
    app.extensions["oidc_client"] = oidc
    app.extensions["ldap_client"] = ldap
    app.extensions["password_pusher_client"] = password_pusher
    app.extensions["netbox_client"] = netbox_environment
    app.extensions["netbox_client_injected"] = netbox_client is not None

    pve_environment = pve_client or PVEClient.from_environment()
    app.extensions["pve_client"] = pve_environment
    app.extensions["pve_client_injected"] = pve_client is not None

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
                _resolve_pve_client(app),
                password_pusher,
                _resolve_netbox_client(app),
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
        client = _resolve_pve_client(app)
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

    @app.cli.command("check-ldap")
    def check_ldap_command():
        """Vérifie TLS et le bind de service LDAP sans afficher de secret."""
        if ldap is None:
            raise click.ClickException("LDAP/LDAPS n'est pas configuré.")
        try:
            ldap.check_connection()
        except LDAPUnavailable as error:
            raise click.ClickException(str(error)) from error
        click.echo("Connexion LDAP/LDAPS et bind de service validés.")

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.cli.command("check-netbox")
    def check_netbox_command():
        """Vérifie TLS et le token API NetBox."""
        netbox = _resolve_netbox_client(app)
        if netbox is None:
            raise click.ClickException("NetBox n'est pas configuré.")
        try:
            netbox.check_connection()
        except NetBoxUnavailable as error:
            raise click.ClickException(str(error)) from error
        click.echo("Connexion NetBox et token API validés.")

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
            render_prometheus_metrics(_resolve_pve_client(app)),
            content_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/")
    def home():
        return render_template(
            "index.html",
            local_auth_enabled=(
                app.config["PORTAL_LOCAL_AUTH_ENABLED"] or ldap is not None
            ),
            oidc_enabled=oidc is not None,
        )

    @app.post("/login")
    def login():
        if not app.config["PORTAL_LOCAL_AUTH_ENABLED"] and ldap is None:
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
        stored_user = (
            db.session.scalar(select(User).where(User.username == username))
            if isinstance(username, str)
            else None
        )
        password_hash = (
            stored_user.password_hash
            if stored_user is not None and stored_user.auth_provider == "local"
            else app.config["PORTAL_DUMMY_PASSWORD_HASH"]
        )
        local_valid = (
            app.config["PORTAL_LOCAL_AUTH_ENABLED"]
            and stored_user is not None
            and stored_user.auth_provider == "local"
            and isinstance(password, str)
            and check_password_hash(password_hash, password)
        )
        user = stored_user if local_valid else None
        ldap_identity = None
        if (
            user is None
            and ldap is not None
            and isinstance(username, str)
            and isinstance(password, str)
            and not (stored_user is not None and stored_user.auth_provider == "local")
        ):
            try:
                ldap_identity = ldap.authenticate(username, password)
            except LDAPAccessDenied:
                _add_audit(
                    action="authentication.ldap_login",
                    target_type="user",
                    target_id=throttle_key,
                    outcome="denied",
                    details={"reason": "group_denied"},
                )
                db.session.commit()
                return jsonify(error="ldap_access_denied"), 403
            except LDAPUnavailable:
                _add_audit(
                    action="authentication.ldap_login",
                    target_type="provider",
                    target_id="ldap",
                    outcome="failure",
                    details={"reason": "provider_unavailable"},
                )
                db.session.commit()
                return jsonify(error="ldap_unavailable"), 503
            if ldap_identity is not None:
                user = _find_or_create_ldap_user(app, ldap_identity)
                user.role = ldap_identity.role
        if (
            user is None
            or not user.is_active
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

        authentication = "ldap" if ldap_identity is not None else "local"
        csrf_token = establish_session(user, authentication)
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
            settings={
                "guest_password_min_length": _guest_password_min_length(),
                "static_ipv4_networks": _static_ipv4_networks_text(),
                "default_vm_lifetime_days": _default_vm_lifetime_days(),
                "max_vm_lifetime_days": _max_vm_lifetime_days(),
                "expiration_warning_days": _expiration_warning_days(),
            },
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
                        "Le mot de passe doit contenir entre 1 et 256 caractères."  # nosec B105
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
        return jsonify(nodes=_resolve_pve_client(app).list_nodes())

    @app.get("/api/nodes/<node>/isos")
    @login_required
    def list_isos(node: str):
        try:
            validate_node_name(node)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400
        return jsonify(node=node, isos=_resolve_pve_client(app).list_isos(node))

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
            and not _resolve_pve_client(app).is_template_available(
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

    @app.get("/api/network-profiles")
    @login_required
    def list_network_profiles():
        profiles = db.session.scalars(
            select(NetworkProfile)
            .where(NetworkProfile.enabled.is_(True))
            .order_by(NetworkProfile.label)
        ).all()
        return jsonify(
            profiles=[
                {
                    "slug": profile.slug,
                    "label": profile.label,
                    "cidr": profile.cidr,
                    "gateway": profile.gateway,
                    "dns_servers": profile.dns_servers.split(","),
                    "vlan_tag": profile.vlan_tag,
                    "netbox_managed": profile.netbox_prefix_id is not None,
                    "allow_manual_ip": profile.allow_manual_ip,
                    "allow_automatic_ip": profile.allow_automatic_ip,
                }
                for profile in profiles
            ]
        )

    @app.get("/api/admin/integrations/netbox")
    @login_required
    @role_required("admin")
    def get_netbox_configuration():
        configuration = db.session.get(NetBoxConfiguration, 1)
        fallback = app.extensions.get("netbox_client")
        return jsonify(
            integration={
                "configured": configuration is not None or fallback is not None,
                "source": "portal"
                if configuration is not None
                else ("environment" if fallback is not None else "none"),
                "base_url": configuration.base_url
                if configuration is not None
                else (fallback.base_url if isinstance(fallback, NetBoxClient) else ""),
                "token_configured": configuration is not None or fallback is not None,
                "ca_configured": bool(
                    configuration.ca_certificate
                    if configuration is not None
                    else (
                        fallback.ca_bundle or fallback.ca_certificate
                        if isinstance(fallback, NetBoxClient)
                        else False
                    )
                ),
                "enabled": configuration.enabled
                if configuration is not None
                else fallback is not None,
            }
        )

    @app.put("/api/admin/integrations/netbox")
    @login_required
    @role_required("admin")
    @csrf_protected
    def save_netbox_configuration():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            integration_request = NetBoxConfigurationRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400
        configuration = db.session.get(NetBoxConfiguration, 1)
        try:
            api_token = integration_request.api_token or (
                decrypt_integration_secret(
                    configuration.api_token_ciphertext,
                    app.config["PORTAL_SESSION_SECRET"],
                    purpose="netbox-api-token",
                )
                if configuration is not None
                else None
            )
        except IntegrationSecretError:
            return jsonify(errors={"api_token": "Le token enregistré est illisible; remplacez-le."}), 409  # nosec B105
        if not api_token:
            return jsonify(errors={"api_token": "Le token NetBox est requis."}), 400  # nosec B105
        try:
            ca_certificate = _updated_ca_certificate(
                current=configuration.ca_certificate if configuration else None,
                supplied=integration_request.ca_certificate,
                clear=integration_request.clear_ca,
            )
        except ValueError as error:
            return jsonify(errors={"ca_certificate": str(error)}), 400
        candidate = NetBoxClient(
            base_url=integration_request.base_url,
            api_token=api_token,
            ca_certificate=ca_certificate or "",
        )
        connection_client = (
            app.extensions["netbox_client"]
            if app.extensions.get("netbox_client_injected")
            else candidate
        )
        if integration_request.enabled:
            try:
                connection_client.check_connection()
            except NetBoxUnavailable as error:
                return jsonify(errors={"connection": str(error)}), 502
        encrypted_token = encrypt_integration_secret(
            api_token,
            app.config["PORTAL_SESSION_SECRET"],
            purpose="netbox-api-token",
        )
        if configuration is None:
            configuration = NetBoxConfiguration(id=1)
            db.session.add(configuration)
        configuration.base_url = integration_request.base_url
        configuration.api_token_ciphertext = encrypted_token
        configuration.ca_certificate = ca_certificate
        configuration.enabled = integration_request.enabled
        configuration.updated_by_id = g.current_user.id
        _add_audit(
            action="integration.netbox.update",
            target_type="integration",
            target_id="netbox",
            outcome="success",
            actor_user_id=g.current_user.id,
            details={
                "base_url": configuration.base_url,
                "enabled": configuration.enabled,
                "ca_configured": bool(configuration.ca_certificate),
            },
        )
        db.session.commit()
        return jsonify(
            integration={
                "configured": True,
                "source": "portal",
                "base_url": configuration.base_url,
                "token_configured": True,  # nosec B105
                "ca_configured": bool(configuration.ca_certificate),
                "enabled": configuration.enabled,
            }
        )

    @app.get("/api/admin/integrations/proxmox")
    @login_required
    @role_required("admin")
    def get_proxmox_configuration():
        configuration = db.session.get(ProxmoxConfiguration, 1)
        fallback = app.extensions["pve_client"]
        return jsonify(
            integration={
                "configured": True,
                "source": "portal" if configuration is not None else "environment",
                "api_url": configuration.api_url
                if configuration is not None
                else getattr(fallback, "api_url", ""),
                "token_id": configuration.token_id
                if configuration is not None
                else getattr(fallback, "token_id", ""),
                "token_configured": True,  # nosec B105
                "ca_configured": bool(
                    configuration.ca_certificate
                    if configuration is not None
                    else getattr(fallback, "ca_certificate", "")
                ),
                "enabled": configuration.enabled
                if configuration is not None
                else True,
            }
        )

    @app.put("/api/admin/integrations/proxmox")
    @login_required
    @role_required("admin")
    @csrf_protected
    def save_proxmox_configuration():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            integration_request = ProxmoxConfigurationRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400
        configuration = db.session.get(ProxmoxConfiguration, 1)
        try:
            token_secret = integration_request.token_secret or (
                decrypt_integration_secret(
                    configuration.token_secret_ciphertext,
                    app.config["PORTAL_SESSION_SECRET"],
                    purpose="proxmox-token-secret",
                )
                if configuration is not None
                else None
            )
        except IntegrationSecretError:
            return jsonify(errors={"token_secret": "Le secret enregistré est illisible; remplacez-le."}), 409  # nosec B105
        if not token_secret:
            return jsonify(errors={"token_secret": "Le secret du token est requis."}), 400  # nosec B105
        try:
            ca_certificate = _updated_ca_certificate(
                current=configuration.ca_certificate if configuration else None,
                supplied=integration_request.ca_certificate,
                clear=integration_request.clear_ca,
            )
        except ValueError as error:
            return jsonify(errors={"ca_certificate": str(error)}), 400
        candidate = PVEClient(
            api_url=integration_request.api_url,
            token_id=integration_request.token_id,
            token_secret=token_secret,
            ca_certificate=ca_certificate or "",
        )
        connection_client = (
            app.extensions["pve_client"]
            if app.extensions.get("pve_client_injected")
            else candidate
        )
        if integration_request.enabled:
            try:
                nodes = connection_client.list_nodes()
            except (PVETransportError, PVEHTTPError, PVEProtocolError):
                return jsonify(errors={"connection": "Connexion Proxmox impossible; vérifiez l'URL, le token et la CA."}), 502
            if not nodes:
                return jsonify(errors={"connection": "Aucun nœud Proxmox visible avec ce token."}), 422
        encrypted_secret = encrypt_integration_secret(
            token_secret,
            app.config["PORTAL_SESSION_SECRET"],
            purpose="proxmox-token-secret",
        )
        if configuration is None:
            configuration = ProxmoxConfiguration(id=1)
            db.session.add(configuration)
        configuration.api_url = integration_request.api_url
        configuration.token_id = integration_request.token_id
        configuration.token_secret_ciphertext = encrypted_secret
        configuration.ca_certificate = ca_certificate
        configuration.enabled = integration_request.enabled
        configuration.updated_by_id = g.current_user.id
        _add_audit(
            action="integration.proxmox.update",
            target_type="integration",
            target_id="proxmox",
            outcome="success",
            actor_user_id=g.current_user.id,
            details={
                "api_url": configuration.api_url,
                "token_id": configuration.token_id,
                "enabled": configuration.enabled,
                "ca_configured": bool(configuration.ca_certificate),
            },
        )
        db.session.commit()
        return jsonify(
            integration={
                "configured": True,
                "source": "portal",
                "api_url": configuration.api_url,
                "token_id": configuration.token_id,
                "token_configured": True,  # nosec B105
                "ca_configured": bool(configuration.ca_certificate),
                "enabled": configuration.enabled,
                "nodes": nodes if integration_request.enabled else [],
            }
        )

    @app.get("/api/admin/network-profiles")
    @login_required
    @role_required("admin")
    def list_admin_network_profiles():
        profiles = db.session.scalars(
            select(NetworkProfile).order_by(NetworkProfile.label)
        ).all()
        return jsonify(
            profiles=[profile.public_dict() for profile in profiles],
            netbox_enabled=_resolve_netbox_client(app) is not None,
        )

    @app.post("/api/admin/network-profiles")
    @login_required
    @role_required("admin")
    @csrf_protected
    def create_network_profile():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            profile_request = NetworkProfileRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400
        netbox = _resolve_netbox_client(app)
        if profile_request.netbox_prefix_id is not None and netbox is None:
            return jsonify(errors={"netbox_prefix_id": "Configurez NetBox avant d'activer ce profil."}), 409
        netbox_vrf_id = None
        if profile_request.netbox_prefix_id is not None:
            try:
                netbox_vrf_id = netbox.validate_prefix(
                    profile_request.netbox_prefix_id, profile_request.cidr
                )
            except NetBoxUnavailable as error:
                return jsonify(errors={"netbox_prefix_id": str(error)}), 502
        profile = NetworkProfile(
            slug=profile_request.slug,
            label=profile_request.label,
            cidr=profile_request.cidr,
            gateway=profile_request.gateway,
            dns_servers=",".join(profile_request.dns_servers),
            bridge=profile_request.bridge,
            vlan_tag=profile_request.vlan_tag,
            netbox_prefix_id=profile_request.netbox_prefix_id,
            netbox_vrf_id=netbox_vrf_id,
            pool_start=profile_request.pool_start,
            pool_end=profile_request.pool_end,
            excluded_ips=",".join(profile_request.excluded_ips),
            allow_manual_ip=profile_request.allow_manual_ip,
            allow_automatic_ip=profile_request.allow_automatic_ip,
            enabled=profile_request.enabled,
        )
        db.session.add(profile)
        _add_audit(
            action="network_profile.create",
            target_type="network_profile",
            target_id=profile.slug,
            outcome="success",
            actor_user_id=g.current_user.id,
            details={"cidr": profile.cidr, "vlan_tag": profile.vlan_tag},
        )
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify(errors={"slug": "Cet identifiant réseau existe déjà."}), 409
        return jsonify(profile=profile.public_dict()), 201

    @app.patch("/api/admin/network-profiles/<slug>")
    @login_required
    @role_required("admin")
    @csrf_protected
    def update_network_profile(slug: str):
        profile = db.session.scalar(
            select(NetworkProfile).where(NetworkProfile.slug == slug).with_for_update()
        )
        if profile is None:
            return jsonify(error="not_found"), 404
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        current = profile.public_dict()
        current.pop("netbox_managed", None)
        current.pop("netbox_vrf_id", None)
        merged = {**current, **payload, "slug": slug}
        try:
            profile_request = NetworkProfileRequest.from_dict(merged)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400
        netbox = _resolve_netbox_client(app)
        if profile_request.netbox_prefix_id is not None and netbox is None:
            return jsonify(errors={"netbox_prefix_id": "Configurez NetBox avant d'activer ce profil."}), 409
        netbox_vrf_id = None
        if profile_request.netbox_prefix_id is not None:
            try:
                netbox_vrf_id = netbox.validate_prefix(
                    profile_request.netbox_prefix_id, profile_request.cidr
                )
            except NetBoxUnavailable as error:
                return jsonify(errors={"netbox_prefix_id": str(error)}), 502
        profile.label = profile_request.label
        profile.cidr = profile_request.cidr
        profile.gateway = profile_request.gateway
        profile.dns_servers = ",".join(profile_request.dns_servers)
        profile.bridge = profile_request.bridge
        profile.vlan_tag = profile_request.vlan_tag
        profile.netbox_prefix_id = profile_request.netbox_prefix_id
        profile.netbox_vrf_id = netbox_vrf_id
        profile.pool_start = profile_request.pool_start
        profile.pool_end = profile_request.pool_end
        profile.excluded_ips = ",".join(profile_request.excluded_ips)
        profile.allow_manual_ip = profile_request.allow_manual_ip
        profile.allow_automatic_ip = profile_request.allow_automatic_ip
        profile.enabled = profile_request.enabled
        _add_audit(
            action="network_profile.update",
            target_type="network_profile",
            target_id=profile.slug,
            outcome="success",
            actor_user_id=g.current_user.id,
            details={"enabled": profile.enabled, "vlan_tag": profile.vlan_tag},
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

    @app.get("/api/admin/settings")
    @login_required
    @role_required("admin")
    def get_admin_settings():
        return jsonify(
            settings={
                "guest_password_min_length": _guest_password_min_length(),
                "static_ipv4_networks": _static_ipv4_networks_text(),
                "default_vm_lifetime_days": _default_vm_lifetime_days(),
                "max_vm_lifetime_days": _max_vm_lifetime_days(),
                "expiration_warning_days": _expiration_warning_days(),
            }
        )

    @app.patch("/api/admin/settings")
    @login_required
    @role_required("admin")
    @csrf_protected
    def update_admin_settings():
        payload = request.get_json(silent=True)
        allowed_settings = {
            "guest_password_min_length",
            "static_ipv4_networks",
            "default_vm_lifetime_days",
            "max_vm_lifetime_days",
            "expiration_warning_days",
        }
        if not isinstance(payload, dict) or not payload or set(payload) - allowed_settings:
            return jsonify(errors={"body": "Paramètre non autorisé."}), 400
        minimum = payload.get(
            "guest_password_min_length", _guest_password_min_length()
        )
        networks_text = payload.get(
            "static_ipv4_networks", _static_ipv4_networks_text()
        )
        default_lifetime = payload.get(
            "default_vm_lifetime_days", _default_vm_lifetime_days()
        )
        maximum_lifetime = payload.get(
            "max_vm_lifetime_days", _max_vm_lifetime_days()
        )
        warning_days = payload.get(
            "expiration_warning_days", _expiration_warning_days()
        )
        if type(minimum) is not int or not 1 <= minimum <= 256:
            return (
                jsonify(
                    errors={
                        "guest_password_min_length": (  # nosec B105
                            "Valeur entière requise entre 1 et 256."
                        )
                    }
                ),
                400,
            )
        lifetime_values = {
            "default_vm_lifetime_days": default_lifetime,
            "max_vm_lifetime_days": maximum_lifetime,
            "expiration_warning_days": warning_days,
        }
        if any(type(value) is not int or not 1 <= value <= 3650 for value in lifetime_values.values()):
            return jsonify(errors={"lifecycle": "Valeurs entières requises entre 1 et 3650 jours."}), 400
        if default_lifetime > maximum_lifetime:
            return jsonify(errors={"default_vm_lifetime_days": "La durée par défaut ne peut pas dépasser la durée maximale."}), 400
        if warning_days > maximum_lifetime:
            return jsonify(errors={"expiration_warning_days": "Le préavis ne peut pas dépasser la durée maximale."}), 400
        try:
            normalized_networks = _normalize_static_ipv4_networks(networks_text)
        except ValueError as error:
            return jsonify(errors={"static_ipv4_networks": str(error)}), 400
        setting = db.session.get(PortalSetting, "guest_password_min_length")
        previous = _guest_password_min_length()
        if setting is None:
            setting = PortalSetting(
                key="guest_password_min_length", value=str(minimum)
            )
            db.session.add(setting)
        else:
            setting.value = str(minimum)
        network_setting = db.session.get(PortalSetting, "static_ipv4_networks")
        if network_setting is None:
            network_setting = PortalSetting(
                key="static_ipv4_networks", value=normalized_networks
            )
            db.session.add(network_setting)
        else:
            network_setting.value = normalized_networks
        for key, value in lifetime_values.items():
            lifecycle_setting = db.session.get(PortalSetting, key)
            if lifecycle_setting is None:
                db.session.add(PortalSetting(key=key, value=str(value)))
            else:
                lifecycle_setting.value = str(value)
        _add_audit(
            action="settings.update",
            target_type="settings",
            target_id="guest_password_min_length",
            outcome="success",
            actor_user_id=g.current_user.id,
            details={
                "previous": previous,
                "current": minimum,
                "static_ipv4_networks": normalized_networks.splitlines(),
                **lifetime_values,
            },
        )
        db.session.commit()
        return jsonify(
            settings={
                "guest_password_min_length": minimum,
                "static_ipv4_networks": normalized_networks,
                **lifetime_values,
            }
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
            nodes = _resolve_pve_client(app).list_nodes()
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
        warning_cutoff = now + timedelta(days=_expiration_warning_days())
        lifecycle_allocations = db.session.scalars(
            select(VMAllocation)
            .where(
                VMAllocation.expires_at.is_not(None),
                VMAllocation.expires_at <= warning_cutoff,
                VMAllocation.status.not_in(("deleted", "failed")),
            )
            .order_by(VMAllocation.expires_at)
            .limit(50)
        ).all()
        lifecycle_items = [
            {
                "id": allocation.id,
                "name": allocation.name,
                "owner": allocation.owner.username,
                "node": allocation.node,
                "vmid": allocation.vmid,
                "status": allocation.status,
                **allocation.lifecycle_dict(
                    warning_days=_expiration_warning_days(), now=now
                ),
            }
            for allocation in lifecycle_allocations
        ]
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
            lifecycle={
                "expired": sum(item["state"] == "expired" for item in lifecycle_items),
                "warning": sum(item["state"] == "warning" for item in lifecycle_items),
                "items": lifecycle_items,
            },
            checked_at=now.isoformat(),
        )

    @app.patch("/api/admin/vms/<vm_id>/lifecycle")
    @login_required
    @role_required("admin")
    @csrf_protected
    def extend_vm_lifecycle(vm_id: str):
        payload = request.get_json(silent=True)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"extend_days"}
            or type(payload["extend_days"]) is not int
            or not 1 <= payload["extend_days"] <= 3650
        ):
            return jsonify(errors={"extend_days": "Valeur entière requise entre 1 et 3650 jours."}), 400
        allocation = db.session.scalar(
            select(VMAllocation).where(VMAllocation.id == vm_id).with_for_update()
        )
        if allocation is None:
            return jsonify(error="not_found"), 404
        if allocation.status in {"deleted", "failed"}:
            return jsonify(error="lifecycle_invalid_state"), 409
        now = datetime.now(UTC)
        previous = allocation.expires_at
        base = previous or now
        if base.tzinfo is None:
            base = base.replace(tzinfo=UTC)
        if base < now:
            base = now
        expires_at = base + timedelta(days=payload["extend_days"])
        if expires_at > now + timedelta(days=_max_vm_lifetime_days()):
            return jsonify(error="lifecycle_limit_exceeded"), 409
        allocation.expires_at = expires_at
        _add_audit(
            action="vm.lifecycle.extend",
            target_type="vm",
            target_id=allocation.id,
            outcome="success",
            actor_user_id=g.current_user.id,
            details={
                "extend_days": payload["extend_days"],
                "previous_expires_at": previous.isoformat() if previous else None,
                "expires_at": expires_at.isoformat(),
                "owner": allocation.owner.username,
            },
        )
        db.session.commit()
        return jsonify(
            lifecycle=allocation.lifecycle_dict(
                warning_days=_expiration_warning_days(), now=now
            )
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
                include_credentials=job.allocation.owner_id == g.current_user.id,
                expiration_warning_days=_expiration_warning_days(),
            )
        )

    @app.get("/api/jobs")
    @login_required
    def list_jobs():
        archived_only = request.args.get("archived") == "only"
        jobs = db.session.scalars(
            select(ProvisioningJob)
            .join(ProvisioningJob.allocation)
            .where(
                VMAllocation.owner_id == g.current_user.id,
                VMAllocation.archived_at.is_not(None)
                if archived_only
                else VMAllocation.archived_at.is_(None),
            )
            .order_by(ProvisioningJob.created_at.desc())
            .limit(25)
        ).all()
        return jsonify(
            jobs=[
                job.public_dict(
                    include_credentials=True,
                    expiration_warning_days=_expiration_warning_days(),
                )
                for job in jobs
            ]
        )

    @app.get("/api/vms/<vm_id>")
    @login_required
    def get_vm_details(vm_id: str):
        allocation = db.session.get(VMAllocation, vm_id)
        if allocation is None or (
            allocation.owner_id != g.current_user.id
            and g.current_user.role != "admin"
        ):
            return jsonify(error="not_found"), 404
        job = allocation.job
        if job is None:  # pragma: no cover - invariant de données
            return jsonify(error="not_found"), 404
        return jsonify(
            details={
                **job.public_dict(
                    include_credentials=allocation.owner_id == g.current_user.id,
                    expiration_warning_days=_expiration_warning_days(),
                ),
                "profile_label": allocation.profile.label
                if allocation.profile is not None
                else None,
                "created_at": allocation.created_at.isoformat(),
                "updated_at": allocation.updated_at.isoformat(),
                "network": {
                    "last_ipv4": allocation.last_ipv4,
                    "observed_at": allocation.network_observed_at.isoformat()
                    if allocation.network_observed_at is not None
                    else None,
                },
                "operations": [
                    operation.public_dict() for operation in allocation.operations
                ],
            }
        )

    @app.get("/api/vms/<vm_id>/network")
    @login_required
    def get_vm_network(vm_id: str):
        allocation = db.session.get(VMAllocation, vm_id)
        if allocation is None:
            return jsonify(error="not_found"), 404
        if (
            allocation.owner_id != g.current_user.id
            and g.current_user.role != "admin"
        ):
            return jsonify(error="not_found"), 404
        if allocation.vmid is None or allocation.status == "deleted":
            return jsonify(
                status="unavailable",
                ipv4=None,
                ipv4_addresses=[],
                last_ipv4=allocation.last_ipv4,
                observed_at=allocation.network_observed_at.isoformat()
                if allocation.network_observed_at is not None
                else None,
                ssh_username=allocation.guest_username,
            )
        if allocation.status != "running":
            return jsonify(
                status="stopped",
                ipv4=allocation.last_ipv4,
                ipv4_addresses=[allocation.last_ipv4]
                if allocation.last_ipv4
                else [],
                last_ipv4=allocation.last_ipv4,
                observed_at=allocation.network_observed_at.isoformat()
                if allocation.network_observed_at is not None
                else None,
                ssh_username=allocation.guest_username,
            )
        try:
            addresses = _resolve_pve_client(app).get_vm_ipv4_addresses(
                allocation.node, allocation.vmid
            )
        except (PVETransportError, PVEHTTPError, PVEProtocolError):
            return jsonify(
                status="temporarily_unavailable",
                ipv4=allocation.last_ipv4,
                ipv4_addresses=[],
                last_ipv4=allocation.last_ipv4,
                observed_at=allocation.network_observed_at.isoformat()
                if allocation.network_observed_at is not None
                else None,
                ssh_username=allocation.guest_username,
            )
        if addresses:
            allocation.last_ipv4 = addresses[0]
            allocation.network_observed_at = datetime.now(UTC)
            db.session.commit()
        return jsonify(
            status="ready" if addresses else "pending",
            ipv4=addresses[0] if addresses else None,
            ipv4_addresses=addresses,
            last_ipv4=allocation.last_ipv4,
            observed_at=allocation.network_observed_at.isoformat()
            if allocation.network_observed_at is not None
            else None,
            ssh_username=allocation.guest_username,
        )

    @app.post("/api/vms/<vm_id>/archive")
    @login_required
    @csrf_protected
    def archive_vm(vm_id: str):
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or set(payload) != {"archived"} or not isinstance(
            payload["archived"], bool
        ):
            return jsonify(errors={"archived": "Un booléen est requis."}), 400
        allocation = db.session.scalar(
            select(VMAllocation)
            .where(VMAllocation.id == vm_id)
            .with_for_update()
        )
        if allocation is None or (
            allocation.owner_id != g.current_user.id
            and g.current_user.role != "admin"
        ):
            return jsonify(error="not_found"), 404
        if payload["archived"] and allocation.status not in {"failed", "deleted"}:
            return jsonify(error="archive_invalid_state"), 409
        if (allocation.archived_at is not None) != payload["archived"]:
            allocation.archived_at = datetime.now(UTC) if payload["archived"] else None
            _add_audit(
                action="vm.archive" if payload["archived"] else "vm.unarchive",
                target_type="vm",
                target_id=allocation.id,
                outcome="success",
                actor_user_id=g.current_user.id,
                details={"status": allocation.status},
            )
            db.session.commit()
        return jsonify(status="archived" if payload["archived"] else "visible")

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
        automatic_ip = vm_request.network_mode == "automatic"

        profile = db.session.scalar(
            select(ImageProfile).where(
                ImageProfile.slug == vm_request.profile,
                ImageProfile.enabled.is_(True),
            )
        )
        if profile is None:
            return jsonify(errors={"profile": "Profil indisponible."}), 400
        network_profile = None
        if vm_request.network_profile:
            network_profile = db.session.scalar(
                select(NetworkProfile).where(
                    NetworkProfile.slug == vm_request.network_profile,
                    NetworkProfile.enabled.is_(True),
                ).with_for_update()
            )
            if network_profile is None:
                return jsonify(errors={"network_profile": "Réseau indisponible."}), 400
        elif profile.source_type == "cloud_init" and db.session.scalar(
            select(func.count(NetworkProfile.id)).where(NetworkProfile.enabled.is_(True))
        ):
            return jsonify(errors={"network_profile": "Sélectionnez un réseau autorisé."}), 400
        if profile.source_type == "cloud_init" and not vm_request.guest_username:
            return (
                jsonify(
                    errors={
                        "guest_username": "Identifiant Linux requis pour ce profil."
                    }
                ),
                400,
            )
        if (
            profile.source_type == "cloud_init"
            and vm_request.node != profile.template_node
        ):
            return (
                jsonify(
                    errors={
                        "node": "Ce template local doit être déployé sur son nœud Proxmox."
                    }
                ),
                400,
            )
        if profile.source_type == "cloud_init" and vm_request.guest_password is None:
            return jsonify(
                errors={"guest_password": "Mot de passe SSH requis."}  # nosec B105
            ), 400
        minimum = _guest_password_min_length()
        if (
            profile.source_type == "cloud_init"
            and vm_request.guest_password is not None
            and len(vm_request.guest_password) < minimum
        ):
            return (
                jsonify(
                    errors={
                        "guest_password": (
                            f"Le mot de passe SSH doit contenir au moins {minimum} "
                            "caractères."
                        )
                    }
                ),
                400,
            )
        lifetime_days = vm_request.lifetime_days or _default_vm_lifetime_days()
        if lifetime_days > _max_vm_lifetime_days():
            return jsonify(errors={"lifetime_days": "Cette durée dépasse la limite définie par l’administrateur."}), 400
        vm_request = replace(vm_request, lifetime_days=lifetime_days)
        if profile.source_type == "iso" and (
            vm_request.guest_username
            or vm_request.guest_password is not None
            or vm_request.network_mode != "dhcp"
            or vm_request.network_profile is not None
        ):
            return (
                jsonify(
                    errors={
                        "guest_username": "Ce profil ISO ne prend pas en charge cloud-init."
                    }
                ),
                400,
            )
        if vm_request.network_mode == "automatic":
            if network_profile is None or not network_profile.allow_automatic_ip:
                return jsonify(errors={"network_mode": "Attribution automatique non autorisée sur ce réseau."}), 400
            selected_ip = _next_available_profile_ip(network_profile)
            if selected_ip is None:
                return jsonify(error="ip_pool_exhausted"), 409
            prefix_length = IPv4Network(network_profile.cidr).prefixlen
            vm_request = replace(
                vm_request,
                network_mode="static",
                ipv4_cidr=f"{selected_ip}/{prefix_length}",
                gateway=network_profile.gateway,
                dns_servers=network_profile.dns_servers.split(","),
            )
        elif vm_request.network_mode == "static":
            if network_profile is not None and not network_profile.allow_manual_ip:
                return jsonify(errors={"network_mode": "Saisie manuelle non autorisée sur ce réseau."}), 400
        if profile.source_type == "cloud_init" and vm_request.network_mode == "static":
            static_error = _validate_static_ipv4_policy(vm_request, network_profile)
            if static_error is not None:
                return jsonify(errors=static_error), 400
        allocation, job, reservation_error = _reserve_allocation(
            g.current_user.id,
            vm_request,
            profile,
            network_profile,
            automatic_ip=automatic_ip,
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
            action_request.action in {"start", "reboot"}
            and allocation.lifecycle_dict()["state"] == "expired"
        ):
            return jsonify(error="vm_expired"), 409
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
        user_id: int,
        vm_request: VMRequest,
        profile: ImageProfile,
        network_profile: NetworkProfile | None,
        *,
        automatic_ip: bool = False,
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
            network_profile_id=network_profile.id if network_profile else None,
            name=vm_request.name,
            node=vm_request.node,
            iso=profile.iso,
            guest_username=vm_request.guest_username,
            network_mode=vm_request.network_mode,
            automatic_ip=automatic_ip,
            ipv4_cidr=vm_request.ipv4_cidr,
            gateway=vm_request.gateway,
            dns_servers=",".join(vm_request.dns_servers) or None,
            network_bridge=network_profile.bridge if network_profile else None,
            vlan_tag=network_profile.vlan_tag if network_profile else None,
            netbox_prefix_id=network_profile.netbox_prefix_id
            if network_profile
            else None,
            netbox_vrf_id=network_profile.netbox_vrf_id
            if network_profile
            else None,
            cpu=vm_request.cpu,
            ram_mb=vm_request.ram_mb,
            disk_gb=vm_request.disk_gb,
            status="queued",
            expires_at=datetime.now(UTC) + timedelta(days=vm_request.lifetime_days or _default_vm_lifetime_days()),
        )
        job = ProvisioningJob(allocation=allocation)
        if vm_request.guest_password is not None:
            job.guest_password_ciphertext = encrypt_guest_password(
                vm_request.guest_password, app.config["PORTAL_SESSION_SECRET"]
            )
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


def _guest_password_min_length() -> int:
    setting = db.session.get(PortalSetting, "guest_password_min_length")
    if setting is None:
        return 8
    try:
        value = int(setting.value)
    except ValueError:
        return 8
    return value if 1 <= value <= 256 else 8


def _integer_portal_setting(key: str, default: int) -> int:
    setting = db.session.get(PortalSetting, key)
    if setting is None:
        return default
    try:
        value = int(setting.value)
    except ValueError:
        return default
    return value if 1 <= value <= 3650 else default


def _default_vm_lifetime_days() -> int:
    return _integer_portal_setting("default_vm_lifetime_days", 90)


def _max_vm_lifetime_days() -> int:
    return _integer_portal_setting("max_vm_lifetime_days", 365)


def _expiration_warning_days() -> int:
    return _integer_portal_setting("expiration_warning_days", 14)


def _static_ipv4_networks_text() -> str:
    setting = db.session.get(PortalSetting, "static_ipv4_networks")
    return setting.value if setting is not None else ""


def _normalize_static_ipv4_networks(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Liste CIDR invalide.")
    networks: list[str] = []
    for raw_value in value.replace(",", "\n").splitlines():
        raw_value = raw_value.strip()
        if not raw_value:
            continue
        try:
            network = IPv4Network(raw_value, strict=True)
        except ValueError as error:
            raise ValueError(f"Réseau IPv4 CIDR invalide : {raw_value}.") from error
        if (
            network.is_multicast
            or network.is_unspecified
            or network.is_loopback
            or network.is_link_local
            or network.is_reserved
            or network.prefixlen < 8
        ):
            raise ValueError(f"Réseau IPv4 non autorisé : {raw_value}.")
        networks.append(str(network))
    return "\n".join(dict.fromkeys(networks))


def _validate_static_ipv4_policy(
    vm_request: VMRequest, network_profile: NetworkProfile | None = None
) -> dict[str, str] | None:
    if vm_request.ipv4_cidr is None:
        return {"ipv4_cidr": "Adresse IPv4 fixe requise."}
    if network_profile is not None:
        allowed = [IPv4Network(network_profile.cidr)]
        if vm_request.gateway != network_profile.gateway:
            return {"gateway": "La passerelle est imposée par le réseau sélectionné."}
        if vm_request.dns_servers != network_profile.dns_servers.split(","):
            return {"dns_servers": "Les DNS sont imposés par le réseau sélectionné."}
        if IPv4Interface(vm_request.ipv4_cidr).network != allowed[0]:
            return {"ipv4_cidr": "Le préfixe doit correspondre au réseau sélectionné."}
    else:
        setting = db.session.scalar(
            select(PortalSetting)
            .where(PortalSetting.key == "static_ipv4_networks")
            .with_for_update()
        )
        allowed = [
            IPv4Network(value)
            for value in (setting.value if setting is not None else "").splitlines()
            if value.strip()
        ]
    address = IPv4Interface(vm_request.ipv4_cidr).ip
    if not allowed:
        return {
            "ipv4_cidr": "Les adresses fixes ne sont pas activées par l'administrateur."
        }
    if not any(address in network for network in allowed):
        return {"ipv4_cidr": "Cette adresse est hors des réseaux autorisés."}
    conflict = db.session.scalar(
        select(VMAllocation.id).where(
            VMAllocation.ipv4_cidr.like(f"{address}/%"),
            VMAllocation.status != "deleted",
        )
    )
    if conflict is not None:
        return {"ipv4_cidr": "Cette adresse est déjà réservée par le portail."}
    return None


def _next_available_profile_ip(
    profile: NetworkProfile, *, after: str | None = None, allocation_id: str | None = None
) -> str | None:
    if profile.pool_start is None or profile.pool_end is None:
        return None
    start = IPv4Address(profile.pool_start)
    end = IPv4Address(profile.pool_end)
    if after is not None:
        start = max(start, IPv4Address(after) + 1)
    excluded = {
        IPv4Address(value)
        for value in profile.excluded_ips.split(",")
        if value
    }
    excluded.add(IPv4Address(profile.gateway))
    statement = select(VMAllocation.id, VMAllocation.ipv4_cidr).where(
        VMAllocation.network_profile_id == profile.id,
        VMAllocation.status != "deleted",
        VMAllocation.ipv4_cidr.is_not(None),
    )
    if allocation_id is not None:
        statement = statement.where(VMAllocation.id != allocation_id)
    used = {
        IPv4Interface(cidr).ip
        for _, cidr in db.session.execute(statement)
        if cidr is not None
    }
    for numeric_address in range(int(start), int(end) + 1):
        candidate = IPv4Address(numeric_address)
        if candidate not in excluded and candidate not in used:
            return str(candidate)
    return None


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
    if (
        not app.config["PORTAL_LOCAL_AUTH_ENABLED"]
        and not app.config["PORTAL_OIDC_ENABLED"]
        and not app.config["PORTAL_LDAP_URI"]
    ):
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


def _configure_ldap(app: Flask, injected_client=None):
    if injected_client is not None:
        app.config["PORTAL_LDAP_ENABLED"] = True
        return injected_client
    if not app.config["PORTAL_LDAP_URI"]:
        app.config["PORTAL_LDAP_ENABLED"] = False
        return None
    try:
        client = LDAPClient(
            uri=app.config["PORTAL_LDAP_URI"],
            base_dn=app.config["PORTAL_LDAP_BASE_DN"],
            user_filter=app.config["PORTAL_LDAP_USER_FILTER"],
            username_attribute=app.config["PORTAL_LDAP_USERNAME_ATTRIBUTE"],
            group_attribute=app.config["PORTAL_LDAP_GROUP_ATTRIBUTE"],
            role_groups={
                "admin": app.config["PORTAL_LDAP_GROUP_ADMIN"],
                "operator": app.config["PORTAL_LDAP_GROUP_OPERATOR"],
                "user": app.config["PORTAL_LDAP_GROUP_USER"],
            },
            bind_dn=app.config["PORTAL_LDAP_BIND_DN"],
            bind_password=app.config["PORTAL_LDAP_BIND_PASSWORD"],
            ca_file=app.config["PORTAL_LDAP_CA_FILE"],
            start_tls=app.config["PORTAL_LDAP_START_TLS"],
        )
    except LDAPConfigurationError as error:
        raise ValueError(f"Configuration LDAP invalide : {error}") from error
    for key, maximum in (
        ("PORTAL_LDAP_DEFAULT_QUOTA_VMS", 100),
        ("PORTAL_LDAP_DEFAULT_QUOTA_CPU", 512),
        ("PORTAL_LDAP_DEFAULT_QUOTA_RAM_MB", 1048576),
        ("PORTAL_LDAP_DEFAULT_QUOTA_DISK_GB", 102400),
    ):
        value = app.config[key]
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError(f"{key} est invalide.")
    app.config["PORTAL_LDAP_ENABLED"] = True
    return client


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


def _configure_netbox(app: Flask, injected_client=None):
    if injected_client is not None:
        app.config["PORTAL_NETBOX_ENABLED"] = True
        return injected_client
    url = app.config["PORTAL_NETBOX_URL"]
    token = app.config["PORTAL_NETBOX_API_TOKEN"]
    if not url and not token:
        app.config["PORTAL_NETBOX_ENABLED"] = False
        return None
    if not url or not token:
        raise ValueError(
            "PORTAL_NETBOX_URL et PORTAL_NETBOX_API_TOKEN doivent être configurés ensemble."
        )
    if not app.config.get("TESTING") and not url.startswith("https://"):
        raise ValueError("PORTAL_NETBOX_URL doit utiliser HTTPS.")
    app.config["PORTAL_NETBOX_ENABLED"] = True
    return NetBoxClient(
        base_url=url,
        api_token=token,
        ca_bundle=app.config["PORTAL_NETBOX_CA_BUNDLE"],
    )


def _resolve_netbox_client(app: Flask):
    fallback = app.extensions.get("netbox_client")
    if app.extensions.get("netbox_client_injected"):
        return fallback
    configuration = db.session.get(NetBoxConfiguration, 1)
    if configuration is None:
        return fallback
    if not configuration.enabled:
        return None
    try:
        token = decrypt_integration_secret(
            configuration.api_token_ciphertext,
            app.config["PORTAL_SESSION_SECRET"],
            purpose="netbox-api-token",
        )
    except IntegrationSecretError as error:
        raise NetBoxUnavailable("La configuration NetBox est illisible.") from error
    return NetBoxClient(
        base_url=configuration.base_url,
        api_token=token,
        ca_certificate=configuration.ca_certificate or "",
    )


def _resolve_pve_client(app: Flask) -> PVEClient:
    fallback = app.extensions["pve_client"]
    if app.extensions.get("pve_client_injected"):
        return fallback
    configuration = db.session.get(ProxmoxConfiguration, 1)
    if configuration is None or not configuration.enabled:
        return fallback
    try:
        token_secret = decrypt_integration_secret(
            configuration.token_secret_ciphertext,
            app.config["PORTAL_SESSION_SECRET"],
            purpose="proxmox-token-secret",
        )
    except IntegrationSecretError as error:
        raise PVETransportError("La configuration Proxmox est illisible.") from error
    return PVEClient(
        api_url=configuration.api_url,
        token_id=configuration.token_id,
        token_secret=token_secret,
        ca_certificate=configuration.ca_certificate or "",
    )


def _updated_ca_certificate(
    *, current: str | None, supplied: str | None, clear: bool
) -> str | None:
    if clear:
        return None
    if supplied is None or not supplied.strip():
        return current
    normalized = supplied.strip() + "\n"
    if "PRIVATE KEY" in normalized:
        raise ValueError("Une CA publique est requise; aucune clé privée n'est acceptée.")
    try:
        certificates = x509.load_pem_x509_certificates(normalized.encode("utf-8"))
    except ValueError as error:
        raise ValueError("Le certificat ou bundle CA PEM est invalide.") from error
    if not certificates:
        raise ValueError("Le bundle CA ne contient aucun certificat.")
    return normalized


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


def _find_or_create_ldap_user(app: Flask, identity: LDAPIdentity) -> User:
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
        auth_provider="ldap",
        external_issuer=identity.issuer,
        external_subject=identity.subject,
        role=identity.role,
        quota_vms=app.config["PORTAL_LDAP_DEFAULT_QUOTA_VMS"],
        quota_cpu=app.config["PORTAL_LDAP_DEFAULT_QUOTA_CPU"],
        quota_ram_mb=app.config["PORTAL_LDAP_DEFAULT_QUOTA_RAM_MB"],
        quota_disk_gb=app.config["PORTAL_LDAP_DEFAULT_QUOTA_DISK_GB"],
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
