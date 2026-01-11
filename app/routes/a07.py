import random
import time
import uuid

import jwt
from flask import Blueprint, jsonify, request

bp = Blueprint("a07", __name__)

USERS = {}  # username -> plaintext password (intentionally bad)
SESSIONS = {}  # token -> username
RESET_TOKENS = {}  # token -> username (no expiry enforcement)

JWT_SECRET = "hardcoded-jwt-secret"  # intentionally weak/hardcoded


def weak_session_token() -> str:
    # GT:OWASP2021_A07_05_START
    return str(uuid.uuid1())  # predictable token
    # GT:OWASP2021_A07_05_END


@bp.post("/register")
def a07_01_register_plaintext():
    body = request.json or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    # GT:OWASP2021_A07_01_START
    USERS[username] = password  # store plaintext password
    # GT:OWASP2021_A07_01_END

    return jsonify({"ok": True, "username": username})


@bp.post("/login")
def a07_02_login_no_lockout():
    body = request.json or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    # GT:OWASP2021_A07_02_START
    if USERS.get(username) != password:  # no rate limiting / lockout
        return jsonify({"error": "bad_credentials"}), 401
    # GT:OWASP2021_A07_02_END

    token = weak_session_token()
    SESSIONS[token] = username
    return jsonify({"ok": True, "token": token})


@bp.get("/login-bypass")
def a07_03_login_bypass_username_only():
    username = request.args.get("username", "")

    # GT:OWASP2021_A07_03_START
    token = weak_session_token()  # creates session without password verification
    SESSIONS[token] = username
    # GT:OWASP2021_A07_03_END

    return jsonify({"ok": True, "token": token})


@bp.post("/reset/request")
def a07_06_reset_token_predictable():
    body = request.json or {}
    username = str(body.get("username", ""))

    # GT:OWASP2021_A07_06_START
    token = str(int(time.time())) + "-" + str(random.randint(1000, 9999))  # predictable
    RESET_TOKENS[token] = username  # no expiry
    # GT:OWASP2021_A07_06_END

    return jsonify({"ok": True, "reset_token": token})


@bp.post("/reset/confirm")
def a07_07_reset_no_expiry_check():
    body = request.json or {}
    token = str(body.get("token", ""))
    new_password = str(body.get("new_password", ""))

    # GT:OWASP2021_A07_07_START
    username = RESET_TOKENS.get(token)  # no expiry validation
    # GT:OWASP2021_A07_07_END

    if not username:
        return jsonify({"error": "invalid_token"}), 400
    USERS[username] = new_password
    return jsonify({"ok": True})


@bp.post("/password/change")
def a07_08_change_password_no_current():
    body = request.json or {}
    username = str(body.get("username", ""))
    new_password = str(body.get("new_password", ""))

    # GT:OWASP2021_A07_08_START
    USERS[username] = new_password  # no current-password check
    # GT:OWASP2021_A07_08_END

    return jsonify({"ok": True})


@bp.post("/jwt/issue")
def a07_09_issue_jwt_weak_secret():
    body = request.json or {}
    username = str(body.get("username", "user"))
    role = str(body.get("role", "user"))

    # GT:OWASP2021_A07_09_START
    token = jwt.encode({"sub": username, "role": role}, JWT_SECRET, algorithm="HS256")  # hardcoded secret
    # GT:OWASP2021_A07_09_END

    return jsonify({"token": token})


@bp.get("/jwt/admin")
def a07_10_decode_jwt_without_verify():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "")

    # GT:OWASP2021_A07_10_START
    payload = jwt.decode(token, options={"verify_signature": False})  # does not verify signature
    # GT:OWASP2021_A07_10_END

    if payload.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"ok": True, "payload": payload})


@bp.get("/jwt/admin-noexp")
def a07_11_decode_jwt_no_expiry():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "")

    # GT:OWASP2021_A07_11_START
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
    # GT:OWASP2021_A07_11_END

    if payload.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"ok": True, "payload": payload})
