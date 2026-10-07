"""Flask application factory and REST API."""
import logging
import os
from functools import wraps

from flask import Flask, Response, g, jsonify, request

from . import __version__, reports, secrets_detector, vuln_scanner
from .access_control import ROLES, AccessControl
from .config import load_config
from .logging_alerts import Alerter, setup_logging
from .store import Store
from .threat_monitor import ThreatMonitor

log = logging.getLogger("ssf")


def create_app(overrides=None):
    cfg = load_config(overrides)
    setup_logging(cfg)
    store = Store(cfg.db_path)
    ac = AccessControl(store)
    alerter = Alerter(cfg, store)
    monitor = ThreatMonitor(cfg, store, alerter)
    new_key = ac.bootstrap(cfg.admin_key)
    if new_key:
        log.warning("Generated admin API key (shown once): %s", new_key)

    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
    app.extensions["ssf"] = {"cfg": cfg, "store": store, "ac": ac, "monitor": monitor}

    def require(perm):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                user = ac.authenticate(request.headers.get("X-API-Key", ""))
                ip = request.remote_addr or ""
                if not user:
                    ac.audit("anonymous", request.method + " " + request.path, perm, False, ip)
                    monitor.ingest({"source": ip, "type": "auth_failure", "payload": request.path})
                    return jsonify(error="authentication required"), 401
                allowed = ac.allowed(user["role"], perm)
                ac.audit(user["name"], request.method + " " + request.path, perm, allowed, ip)
                if not allowed:
                    return jsonify(error="forbidden"), 403
                g.user = user
                return fn(*a, **kw)
            return wrapper
        return deco

    def resolve_target(rel):
        root = os.path.realpath(cfg.scan_root)
        target = os.path.realpath(os.path.join(root, rel or "."))
        if os.path.commonpath([root, target]) != root or not os.path.exists(target):
            return None
        return target

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def dashboard():
        return app.send_static_file("index.html")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", version=__version__)

    @app.post("/api/scan/secrets")
    @require("scan:run")
    def scan_secrets():
        body = request.get_json(silent=True) or {}
        if "text" in body:
            return jsonify(findings=secrets_detector.scan_text(str(body["text"])))
        target = resolve_target(body.get("path"))
        if not target:
            return jsonify(error="invalid path"), 400
        findings = secrets_detector.scan_path(target, cfg.exclude_dirs, cfg.max_file_bytes)
        for f in findings:
            if f["severity"] == "critical":
                alerter.alert("critical", f"{f['type']} exposed in {f['file']}", {"line": f["line"]})
        return jsonify(findings=findings)

    @app.post("/api/scan")
    @require("scan:run")
    def scan_all():
        body = request.get_json(silent=True) or {}
        target = resolve_target(body.get("path"))
        if not target:
            return jsonify(error="invalid path"), 400
        findings, tools = vuln_scanner.scan(target, cfg)
        secrets = secrets_detector.scan_path(target, cfg.exclude_dirs, cfg.max_file_bytes)
        sid = store.add("scans", {"target": os.path.relpath(target, os.path.realpath(cfg.scan_root)),
                                  "findings": findings, "secrets": secrets, "tools": tools,
                                  "user": g.user["name"]})
        if any(f["severity"] in ("high", "critical") for f in findings + secrets):
            alerter.alert("high", f"High-severity findings in scan {sid}")
        return jsonify(scan_id=sid, vulnerabilities=len(findings), secrets=len(secrets), tools=tools), 201

    @app.get("/api/scans")
    @require("scan:read")
    def scans():
        return jsonify([{k: v for k, v in s.items() if k not in ("findings", "secrets")}
                        | {"vulnerabilities": len(s["findings"]), "secrets": len(s["secrets"])}
                        for s in store.list("scans", request.args.get("limit", 50, type=int))])

    @app.get("/api/scans/<int:sid>")
    @require("scan:read")
    def scan_detail(sid):
        s = store.get("scans", sid)
        return (jsonify(s), 200) if s else (jsonify(error="not found"), 404)

    @app.post("/api/threats/events")
    @require("threats:write")
    def threat_event():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="JSON object required"), 400
        return jsonify(monitor.ingest(body)), 201

    @app.post("/api/threats/analyze")
    @require("threats:write")
    def threat_analyze():
        body = request.get_json(silent=True) or {}
        return jsonify(hits=monitor.analyze_log(str(body.get("log", ""))))

    @app.get("/api/threats/status")
    @require("threats:read")
    def threat_status():
        return jsonify(monitor.status(request.args.get("window", 3600, type=int)))

    @app.get("/api/threats/alerts")
    @require("threats:read")
    def alerts():
        return jsonify(store.list("alerts", request.args.get("limit", 100, type=int)))

    @app.get("/api/access/users")
    @require("access:read")
    def users():
        return jsonify(ac.list_users())

    @app.post("/api/access/users")
    @require("access:write")
    def add_user():
        body = request.get_json(silent=True) or {}
        try:
            key = ac.create_user(str(body.get("name", "")), str(body.get("role", "viewer")))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(name=body["name"], role=body.get("role", "viewer"), api_key=key), 201

    @app.put("/api/access/users/<name>/role")
    @require("access:write")
    def change_role(name):
        try:
            ok = ac.set_role(name, str((request.get_json(silent=True) or {}).get("role", "")))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return (jsonify(ok=True), 200) if ok else (jsonify(error="not found"), 404)

    @app.delete("/api/access/users/<name>")
    @require("access:write")
    def revoke(name):
        if name == g.user["name"]:
            return jsonify(error="cannot revoke yourself"), 400
        return (jsonify(ok=True), 200) if ac.revoke(name) else (jsonify(error="not found"), 404)

    @app.get("/api/access/roles")
    @require("access:read")
    def roles():
        return jsonify({r: sorted(p) for r, p in ROLES.items()})

    @app.get("/api/access/audit")
    @require("access:read")
    def audit():
        return jsonify(store.list("audit", request.args.get("limit", 100, type=int)))

    @app.get("/api/reports")
    @require("reports:read")
    def report():
        r = reports.build_report(store, request.args.get("scan_id", type=int))
        fmt = request.args.get("format", "json")
        if fmt == "html":
            return Response(reports.render_html(r), mimetype="text/html")
        if fmt == "text":
            return Response(reports.render_text(r), mimetype="text/plain")
        return jsonify(r)

    return app


def main():
    app = create_app()
    app.run(host=os.environ.get("SSF_HOST", "127.0.0.1"), port=int(os.environ.get("SSF_PORT", "8080")))


if __name__ == "__main__":
    main()
