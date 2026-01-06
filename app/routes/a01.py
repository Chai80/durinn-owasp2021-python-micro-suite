from flask import Blueprint, jsonify, request

bp = Blueprint("a01", __name__)

USERS = {
    "1": {"id": "1", "username": "alice", "email": "alice@example.com", "salary": 120000},
    "2": {"id": "2", "username": "bob", "email": "bob@example.com", "salary": 95000},
    "3": {"id": "3", "username": "carol", "email": "carol@example.com", "salary": 200000},
}

ORDERS = {
    "o1": {"id": "o1", "user_id": "1", "total": 19.99, "items": ["shirt"]},
    "o2": {"id": "o2", "user_id": "2", "total": 299.00, "items": ["headphones"]},
}

ACCOUNTS = {
    "1": {"user_id": "1", "balance": 1000},
    "2": {"user_id": "2", "balance": 2500},
}

SETTINGS = {
    "1": {"user_id": "1", "email_notifications": True},
    "2": {"user_id": "2", "email_notifications": False},
}

TICKETS = {
    "t1": {"id": "t1", "user_id": "1", "subject": "Refund", "notes": "contains sensitive info"},
    "t2": {"id": "t2", "user_id": "2", "subject": "Billing", "notes": "card last4 4242"},
}


def current_user():
    # Test-only identity context via headers.
    return {
        "id": request.headers.get("X-User-Id", "1"),
        "role": request.headers.get("X-User-Role", "user"),
    }


@bp.get("/users/<user_id>")
def a01_01_idor_user(user_id: str):
    # GT:OWASP2021_A01_01_START
    user = USERS.get(user_id)  # missing ownership / role check
    # GT:OWASP2021_A01_01_END
    if not user:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"viewer": current_user(), "record": user})


@bp.get("/orders/<order_id>")
def a01_02_idor_order(order_id: str):
    # GT:OWASP2021_A01_02_START
    order = ORDERS.get(order_id)  # missing ownership check
    # GT:OWASP2021_A01_02_END
    if not order:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"viewer": current_user(), "order": order})


@bp.post("/users/<user_id>/role")
def a01_03_privilege_escalation(user_id: str):
    new_role = request.json.get("role", "user") if request.is_json else "user"

    # GT:OWASP2021_A01_03_START
    if user_id in USERS:
        USERS[user_id]["role"] = new_role  # no admin authorization
    # GT:OWASP2021_A01_03_END

    return jsonify({"ok": True, "updated": USERS.get(user_id)})


@bp.get("/admin/metrics")
def a01_04_query_param_admin():
    # GT:OWASP2021_A01_04_START
    if request.args.get("is_admin") != "true":  # trusts client-controlled flag
        return jsonify({"error": "forbidden"}), 403
    # GT:OWASP2021_A01_04_END
    return jsonify({"ok": True, "secret_metrics": {"revenue": 123456}})


@bp.delete("/posts/<post_id>")
def a01_05_delete_without_authz(post_id: str):
    # Simulated destructive action
    # GT:OWASP2021_A01_05_START
    # Missing authorization check before deletion
    deleted = {"post_id": post_id, "deleted": True}
    # GT:OWASP2021_A01_05_END
    return jsonify(deleted)


@bp.get("/accounts/<user_id>/balance")
def a01_06_view_other_balance(user_id: str):
    # GT:OWASP2021_A01_06_START
    acct = ACCOUNTS.get(user_id)  # missing ownership check
    # GT:OWASP2021_A01_06_END
    if not acct:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"viewer": current_user(), "account": acct})


@bp.post("/transfer")
def a01_07_transfer_from_anyone():
    body = request.json or {}
    from_id = str(body.get("from_user_id", ""))
    to_id = str(body.get("to_user_id", ""))
    amount = float(body.get("amount", 0))

    # GT:OWASP2021_A01_07_START
    from_acct = ACCOUNTS.get(from_id)  # attacker controls from_user_id
    to_acct = ACCOUNTS.get(to_id)
    # GT:OWASP2021_A01_07_END

    if not from_acct or not to_acct:
        return jsonify({"error": "bad_accounts"}), 400
    if amount <= 0:
        return jsonify({"error": "bad_amount"}), 400

    from_acct["balance"] -= amount
    to_acct["balance"] += amount
    return jsonify({"ok": True, "from": from_acct, "to": to_acct, "viewer": current_user()})


@bp.post("/settings/update")
def a01_08_update_settings_for_any_user():
    body = request.json or {}
    user_id = str(body.get("user_id", ""))
    email_notifications = bool(body.get("email_notifications", False))

    # GT:OWASP2021_A01_08_START
    SETTINGS[user_id] = {"user_id": user_id, "email_notifications": email_notifications}  # no authz
    # GT:OWASP2021_A01_08_END

    return jsonify({"ok": True, "settings": SETTINGS.get(user_id), "viewer": current_user()})


@bp.get("/reports/export")
def a01_09_internal_header_bypass():
    # GT:OWASP2021_A01_09_START
    if request.headers.get("X-Internal") != "1":  # weak/bypassable gate
        return jsonify({"error": "forbidden"}), 403
    # GT:OWASP2021_A01_09_END
    return jsonify({"ok": True, "dump": {"users": list(USERS.values()), "orders": list(ORDERS.values())}})


@bp.get("/tickets/<ticket_id>")
def a01_10_view_any_ticket(ticket_id: str):
    # GT:OWASP2021_A01_10_START
    ticket = TICKETS.get(ticket_id)  # missing ownership check
    # GT:OWASP2021_A01_10_END
    if not ticket:
        return jsonify({"error": "not_found"}), 404
    return jsonify({"viewer": current_user(), "ticket": ticket})
