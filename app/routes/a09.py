import logging
import os

from flask import Blueprint, jsonify, request

bp = Blueprint("a09", __name__)

os.makedirs("tmp", exist_ok=True)

logging.basicConfig(
    filename="tmp/app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("a09")


@bp.post("/login")
def a09_01_log_password():
    body = request.json or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    # GT:OWASP2021_A09_01_START
    logger.info("login_attempt username=%s password=%s", username, password)  # sensitive logging
    # GT:OWASP2021_A09_01_END

    return jsonify({"ok": True})


@bp.get("/token")
def a09_02_log_auth_header():
    auth = request.headers.get("Authorization", "")

    # GT:OWASP2021_A09_02_START
    logger.info("auth_header=%s", auth)  # logs bearer tokens
    # GT:OWASP2021_A09_02_END

    return jsonify({"ok": True})


@bp.post("/payment")
def a09_03_log_card_data():
    body = request.json or {}
    card = str(body.get("card_number", ""))

    # GT:OWASP2021_A09_03_START
    logger.info("payment card_number=%s", card)  # sensitive logging
    # GT:OWASP2021_A09_03_END

    return jsonify({"ok": True})


@bp.post("/log/raw")
def a09_04_log_injection_forging():
    msg = (request.json or {}).get("msg", "")

    # GT:OWASP2021_A09_04_START
    logger.info(msg)  # log forging/injection (newlines, fake severity, etc.)
    # GT:OWASP2021_A09_04_END

    return jsonify({"ok": True})


@bp.post("/log/format")
def a09_05_format_string_logging():
    fmt = (request.json or {}).get("fmt", "%s")
    val = (request.json or {}).get("val", "x")

    # GT:OWASP2021_A09_05_START
    logger.info(fmt % val)  # user-controlled formatting
    # GT:OWASP2021_A09_05_END

    return jsonify({"ok": True})


@bp.get("/errors/swallow")
def a09_06_swallow_exceptions():
    try:
        1 / 0
    except Exception:
        # GT:OWASP2021_A09_06_START
        pass  # exception swallowed, no logging/alerting
        # GT:OWASP2021_A09_06_END
    return jsonify({"ok": True})


@bp.get("/logging/disable")
def a09_07_disable_logging():
    # GT:OWASP2021_A09_07_START
    logger.disabled = True  # disables logging
    # GT:OWASP2021_A09_07_END
    return jsonify({"ok": True})


@bp.post("/admin/change-email")
def a09_08_no_audit_log():
    body = request.json or {}
    user_id = str(body.get("user_id", ""))
    new_email = str(body.get("new_email", ""))

    # GT:OWASP2021_A09_08_START
    # Security-sensitive change without audit logging.
    _ = (user_id, new_email)
    # GT:OWASP2021_A09_08_END

    return jsonify({"ok": True})


@bp.get("/logfile")
def a09_09_expose_logs():
    # GT:OWASP2021_A09_09_START
    with open("tmp/app.log", "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()
    # GT:OWASP2021_A09_09_END
    return jsonify({"log": data[:2000]})


@bp.get("/monitoring/none")
def a09_10_no_monitoring_hook():
    # GT:OWASP2021_A09_10_START
    # Placeholder: critical paths without alerts/monitoring hooks.
    # (Many tools won't detect "missing monitoring"; this is an experiment control.)
    # GT:OWASP2021_A09_10_END
    return jsonify({"ok": True})
