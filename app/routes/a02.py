import base64
import hashlib
import hmac
import os
import random
import uuid

from flask import Blueprint, jsonify, request

bp = Blueprint("a02", __name__)

VAULT = {}


@bp.post("/hash/md5")
def a02_01_md5():
    pw = (request.json or {}).get("password", "")

    # GT:OWASP2021_A02_01_START
    digest = hashlib.md5(pw.encode("utf-8")).hexdigest()
    # GT:OWASP2021_A02_01_END

    return jsonify({"algo": "md5", "hash": digest})


@bp.post("/hash/sha1")
def a02_02_sha1():
    pw = (request.json or {}).get("password", "")

    # GT:OWASP2021_A02_02_START
    digest = hashlib.sha1(pw.encode("utf-8")).hexdigest()
    # GT:OWASP2021_A02_02_END

    return jsonify({"algo": "sha1", "hash": digest})


@bp.post("/hash/sha256-nosalt")
def a02_03_sha256_nosalt():
    pw = (request.json or {}).get("password", "")

    # GT:OWASP2021_A02_03_START
    digest = hashlib.sha256(pw.encode("utf-8")).hexdigest()  # unsalted password hash
    # GT:OWASP2021_A02_03_END

    return jsonify({"algo": "sha256", "hash": digest})


@bp.post("/kdf/pbkdf2-weak")
def a02_04_pbkdf2_weak():
    pw = (request.json or {}).get("password", "password")

    # GT:OWASP2021_A02_04_START
    salt = b"static-salt"  # static salt
    key = hashlib.pbkdf2_hmac("sha1", pw.encode("utf-8"), salt, 1000, dklen=32)  # weak params
    # GT:OWASP2021_A02_04_END

    return jsonify({"kdf": "pbkdf2_hmac", "key_hex": key.hex()})


@bp.get("/token/mathrandom")
def a02_05_mathrandom_token():
    # GT:OWASP2021_A02_05_START
    token = str(random.random())  # not cryptographically secure
    # GT:OWASP2021_A02_05_END
    return jsonify({"token": token})


@bp.get("/token/uuid1")
def a02_06_uuid1_token():
    # GT:OWASP2021_A02_06_START
    token = str(uuid.uuid1())  # time-based, predictable
    # GT:OWASP2021_A02_06_END
    return jsonify({"token": token})


@bp.post("/mac/hmac-hardcoded")
def a02_07_hmac_hardcoded_key():
    data = (request.json or {}).get("data", "")

    # GT:OWASP2021_A02_07_START
    key = b"hardcoded-secret-key"
    mac = hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()
    # GT:OWASP2021_A02_07_END

    return jsonify({"mac": mac})


@bp.post("/encrypt/base64")
def a02_08_base64_is_not_encryption():
    plaintext = (request.json or {}).get("plaintext", "")

    # GT:OWASP2021_A02_08_START
    ciphertext = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")  # reversible encoding
    # GT:OWASP2021_A02_08_END

    return jsonify({"ciphertext": ciphertext})


@bp.post("/encrypt/xor")
def a02_09_xor_cipher():
    plaintext = (request.json or {}).get("plaintext", "")
    key = b"K"  # 1-byte key

    # GT:OWASP2021_A02_09_START
    ct = bytes([b ^ key[0] for b in plaintext.encode("utf-8")])  # weak homemade crypto
    # GT:OWASP2021_A02_09_END

    return jsonify({"ciphertext_b64": base64.b64encode(ct).decode("ascii")})


@bp.post("/vault/store-plaintext")
def a02_10_store_plaintext():
    name = (request.json or {}).get("name", "secret")
    value = (request.json or {}).get("value", "")

    # GT:OWASP2021_A02_10_START
    VAULT[name] = value  # stored unencrypted
    # GT:OWASP2021_A02_10_END

    # Also write to disk (demo only)
    os.makedirs("tmp", exist_ok=True)
    with open("tmp/vault.txt", "a", encoding="utf-8") as f:
        f.write(f"{name}={value}\n")

    return jsonify({"ok": True, "name": name})
