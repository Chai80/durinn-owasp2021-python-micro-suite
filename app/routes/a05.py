import os
import ssl
import traceback

from flask import Blueprint, Response, current_app, jsonify, request

bp = Blueprint("a05", __name__)


@bp.get("/env")
def a05_01_expose_env():
    # GT:OWASP2021_A05_01_START
    return jsonify(dict(os.environ))  # exposes environment variables
    # GT:OWASP2021_A05_01_END


@bp.get("/config")
def a05_02_expose_config():
    # GT:OWASP2021_A05_02_START
    return jsonify({k: str(v) for k, v in current_app.config.items()})  # exposes config
    # GT:OWASP2021_A05_02_END


@bp.get("/set-insecure-cookie")
def a05_03_insecure_cookie_flags():
    resp = Response("ok", mimetype="text/plain")

    # GT:OWASP2021_A05_03_START
    resp.set_cookie("sid", "insecure", httponly=False, secure=False, samesite=None)
    # GT:OWASP2021_A05_03_END

    return resp


@bp.get("/boom")
def a05_04_trigger_error():
    raise RuntimeError("boom")


def install_insecure_tls_context():
    # GT:OWASP2021_A05_05_START
    ssl._create_default_https_context = ssl._create_unverified_context  # disable TLS verification globally
    # GT:OWASP2021_A05_05_END


@bp.before_app_request
def a05_06_insecure_tls_hook():
    # installs insecure TLS settings once per process
    install_insecure_tls_context()


@bp.get("/cors")
def a05_07_wildcard_cors_demo():
    # Response headers are added in main.py after_request hook
    return jsonify({"ok": True})


@bp.get("/stacktrace")
def a05_08_stacktrace_leak():
    try:
        1 / 0
    except Exception:
        # GT:OWASP2021_A05_08_START
        return Response(traceback.format_exc(), mimetype="text/plain")  # stack trace leak
        # GT:OWASP2021_A05_08_END


@bp.get("/debug")
def a05_09_debug_endpoint():
    # GT:OWASP2021_A05_09_START
    return jsonify({"debug": True, "note": "debug endpoints should not be enabled in prod"})
    # GT:OWASP2021_A05_09_END


@bp.get("/headers")
def a05_10_insecure_headers_demo():
    # Headers are set in after_request hook in main.py
    return jsonify({"ok": True})
