from __future__ import annotations

import os
from functools import wraps

from flask import Flask, jsonify, request, session
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash

from .pve import PVEClient, PVEHTTPError, PVEProtocolError, PVETransportError
from .validation import ValidationError, VMRequest


def create_app(test_config: dict | None = None, *, pve_client=None) -> Flask:
    """Crée l'application; l'accès PVE peut être injecté pendant les tests."""
    app = Flask(__name__)
    app.config.from_mapping(
        JSON_SORT_KEYS=True,
        MAX_CONTENT_LENGTH=64 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("PORTAL_SESSION_COOKIE_SECURE", "true").lower() not in {"0", "false", "no"},
        PORTAL_ADMIN_USERNAME=os.environ.get("PORTAL_ADMIN_USERNAME", "").strip(),
        PORTAL_ADMIN_PASSWORD_HASH=os.environ.get("PORTAL_ADMIN_PASSWORD_HASH", "").strip(),
        PORTAL_SESSION_SECRET=os.environ.get("PORTAL_SESSION_SECRET", ""),
    )
    if test_config:
        app.config.update(test_config)

    required_auth = ("PORTAL_ADMIN_USERNAME", "PORTAL_ADMIN_PASSWORD_HASH", "PORTAL_SESSION_SECRET")
    missing_auth = [key for key in required_auth if not app.config.get(key)]
    if missing_auth:
        raise ValueError("Variables d'environnement d'authentification manquantes: " + ", ".join(missing_auth))
    app.secret_key = app.config["PORTAL_SESSION_SECRET"]

    client = pve_client or PVEClient.from_environment()
    app.extensions["pve_client"] = client

    @app.before_request
    def reject_oversized_request():
        if request.content_length is not None and request.content_length > app.config["MAX_CONTENT_LENGTH"]:
            return jsonify(error="payload_too_large"), 413

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

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("authenticated") is not True:
                return jsonify(error="authentication_required"), 401
            return view(*args, **kwargs)
        return wrapped

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/")
    def home():
        return "<!doctype html><title>Portail Proxmox</title><h1>Portail Proxmox</h1><p>MVP de provisionnement sécurisé.</p>"

    @app.post("/login")
    def login():
        credentials = request.get_json(silent=True)
        if not isinstance(credentials, dict):
            return jsonify(error="invalid_credentials"), 401
        username, password = credentials.get("username"), credentials.get("password")
        if not isinstance(username, str) or not isinstance(password, str) or username != app.config["PORTAL_ADMIN_USERNAME"] or not check_password_hash(app.config["PORTAL_ADMIN_PASSWORD_HASH"], password):
            return jsonify(error="invalid_credentials"), 401
        session.clear()
        session["authenticated"] = True
        return jsonify(status="authenticated")

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(status="logged_out")

    @app.post("/api/vms")
    @login_required
    def request_vm():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(errors={"body": "Un objet JSON est requis."}), 400
        try:
            vm_request = VMRequest.from_dict(payload)
        except ValidationError as error:
            return jsonify(errors=error.errors), 400

        if not client.is_iso_available(vm_request.node, vm_request.iso):
            return jsonify(errors={"iso": "ISO inaccessible sur le nœud sélectionné."}), 400

        request_id = client.create_vm(vm_request.as_dict())
        return jsonify(status="accepted", request_id=request_id), 202

    return app
