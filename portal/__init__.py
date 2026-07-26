from __future__ import annotations

from flask import Flask, jsonify, request

from .pve import PVEClient
from .validation import ValidationError, VMRequest


def create_app(test_config: dict | None = None, *, pve_client=None) -> Flask:
    """Crée l'application; l'accès PVE peut être injecté pendant les tests."""
    app = Flask(__name__)
    app.config.from_mapping(JSON_SORT_KEYS=True)
    if test_config:
        app.config.update(test_config)

    client = pve_client or PVEClient.from_environment()
    app.extensions["pve_client"] = client

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok")

    @app.get("/")
    def home():
        return "<!doctype html><title>Portail Proxmox</title><h1>Portail Proxmox</h1><p>MVP de provisionnement sécurisé.</p>"

    @app.post("/api/vms")
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
