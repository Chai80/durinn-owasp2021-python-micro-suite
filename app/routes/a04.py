from flask import Blueprint, jsonify, request

bp = Blueprint("a04", __name__)

PRODUCTS = {
    "p1": {"id": "p1", "name": "tshirt", "price": 19.99},
    "p2": {"id": "p2", "name": "headphones", "price": 299.00},
}

STATE = {
    "wallets": {"1": 100.0, "2": 50.0},
    "orders": [],
    "emails": {"1": "alice@example.com"},
    "subscriptions": {"1": False},
    "redeems": set(),
    "profile": {"id": "1", "username": "alice", "tier": "free", "limit": 10},
}


@bp.post("/order/create")
def a04_01_price_tampering():
    body = request.json or {}
    product_id = str(body.get("product_id", "p1"))
    qty = int(body.get("qty", 1))
    client_price = float(body.get("unit_price", 0))  # client-controlled

    # GT:OWASP2021_A04_01_START
    total = qty * client_price  # trusts client for pricing (design flaw)
    # GT:OWASP2021_A04_01_END

    STATE["orders"].append({"product_id": product_id, "qty": qty, "total": total})
    return jsonify({"ok": True, "order": STATE["orders"][-1]})


@bp.post("/order/create2")
def a04_02_shipping_tampering():
    body = request.json or {}
    shipping = float(body.get("shipping_cost", 0))  # client-controlled

    # GT:OWASP2021_A04_02_START
    # Trusting a client-controlled shipping cost can lead to free/negative shipping.
    final = 100 + shipping
    # GT:OWASP2021_A04_02_END

    return jsonify({"ok": True, "final_total": final})


@bp.post("/coupon/apply")
def a04_03_unbounded_discount():
    body = request.json or {}
    subtotal = float(body.get("subtotal", 100))
    discount_pct = float(body.get("discount_pct", 0))

    # GT:OWASP2021_A04_03_START
    total = subtotal * (1 - (discount_pct / 100.0))  # allows >100% or negative discounts
    # GT:OWASP2021_A04_03_END

    return jsonify({"ok": True, "total": total})


@bp.post("/wallet/deposit")
def a04_04_unlimited_deposit():
    body = request.json or {}
    user_id = str(body.get("user_id", "1"))
    amount = float(body.get("amount", 0))

    # GT:OWASP2021_A04_04_START
    STATE["wallets"][user_id] = STATE["wallets"].get(user_id, 0.0) + amount  # no max, no validation
    # GT:OWASP2021_A04_04_END

    return jsonify({"ok": True, "balance": STATE["wallets"][user_id]})


@bp.post("/wallet/withdraw")
def a04_05_negative_withdraw():
    body = request.json or {}
    user_id = str(body.get("user_id", "1"))
    amount = float(body.get("amount", 0))

    # GT:OWASP2021_A04_05_START
    STATE["wallets"][user_id] = STATE["wallets"].get(user_id, 0.0) - amount  # negative amount increases balance
    # GT:OWASP2021_A04_05_END

    return jsonify({"ok": True, "balance": STATE["wallets"][user_id]})


@bp.post("/subscription/activate")
def a04_06_trust_is_paid_flag():
    body = request.json or {}
    user_id = str(body.get("user_id", "1"))
    is_paid = bool(body.get("is_paid", False))

    # GT:OWASP2021_A04_06_START
    STATE["subscriptions"][user_id] = is_paid  # trusts client payment state
    # GT:OWASP2021_A04_06_END

    return jsonify({"ok": True, "active": STATE["subscriptions"][user_id]})


@bp.post("/email/change")
def a04_07_change_email_no_verification():
    body = request.json or {}
    user_id = str(body.get("user_id", "1"))
    new_email = str(body.get("new_email", ""))

    # GT:OWASP2021_A04_07_START
    STATE["emails"][user_id] = new_email  # no re-auth / verification workflow
    # GT:OWASP2021_A04_07_END

    return jsonify({"ok": True, "email": STATE["emails"][user_id]})


@bp.patch("/profile")
def a04_08_mass_assignment():
    body = request.json or {}

    # GT:OWASP2021_A04_08_START
    STATE["profile"].update(body)  # no allowlist of writable fields
    # GT:OWASP2021_A04_08_END

    return jsonify({"ok": True, "profile": STATE["profile"]})


@bp.post("/redeem")
def a04_09_replayable_redeem():
    body = request.json or {}
    code = str(body.get("code", ""))

    # GT:OWASP2021_A04_09_START
    # No idempotency / replay protection: same code can be redeemed repeatedly.
    redeemed = code in STATE["redeems"]
    # GT:OWASP2021_A04_09_END

    # (Intentionally flawed: we still "redeem" it even if already redeemed.)
    STATE["redeems"].add(code)
    return jsonify({"ok": True, "already_redeemed": redeemed})


@bp.post("/bulk/import")
def a04_10_unbounded_bulk_operation():
    body = request.json or {}
    items = body.get("items", [])

    # GT:OWASP2021_A04_10_START
    # No max size/limit — can cause resource exhaustion (design flaw).
    STATE["orders"].extend(items)
    # GT:OWASP2021_A04_10_END

    return jsonify({"ok": True, "count": len(STATE["orders"])})
