import base64
import importlib.machinery
import io
import marshal
import pickle
import subprocess
import tarfile
import urllib.request
import zipfile

import yaml
from flask import Blueprint, Response, jsonify, request

bp = Blueprint("a08", __name__)


@bp.post("/deserialize/pickle")
def a08_01_pickle_loads():
    b64 = (request.json or {}).get("b64", "")

    # GT:OWASP2021_A08_01_START
    obj = pickle.loads(base64.b64decode(b64))  # unsafe deserialization
    # GT:OWASP2021_A08_01_END

    return jsonify({"type": str(type(obj)), "repr": repr(obj)[:200]})


@bp.post("/deserialize/yaml")
def a08_02_yaml_load():
    text = (request.json or {}).get("yaml", "")

    # GT:OWASP2021_A08_02_START
    obj = yaml.load(text, Loader=yaml.Loader)  # unsafe yaml load
    # GT:OWASP2021_A08_02_END

    return jsonify({"repr": repr(obj)[:200]})


@bp.post("/deserialize/marshal")
def a08_03_marshal_loads():
    b64 = (request.json or {}).get("b64", "")

    # GT:OWASP2021_A08_03_START
    obj = marshal.loads(base64.b64decode(b64))  # unsafe deserialization
    # GT:OWASP2021_A08_03_END

    return jsonify({"type": str(type(obj)), "repr": repr(obj)[:200]})


@bp.post("/extract/zip")
def a08_04_zip_extractall():
    b64 = (request.json or {}).get("b64", "")

    # GT:OWASP2021_A08_04_START
    z = zipfile.ZipFile(io.BytesIO(base64.b64decode(b64)))
    z.extractall("tmp/zip_extract")  # Zip Slip risk
    # GT:OWASP2021_A08_04_END

    return jsonify({"ok": True})


@bp.post("/extract/tar")
def a08_05_tar_extractall():
    b64 = (request.json or {}).get("b64", "")

    # GT:OWASP2021_A08_05_START
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(b64))) as tf:
        tf.extractall("tmp/tar_extract")  # path traversal risk
    # GT:OWASP2021_A08_05_END

    return jsonify({"ok": True})


@bp.get("/update/exec")
def a08_06_download_and_exec():
    url = request.args.get("url", "")

    # GT:OWASP2021_A08_06_START
    code = urllib.request.urlopen(url).read().decode("utf-8")  # no integrity check
    exec(code, {})  # executes downloaded code
    # GT:OWASP2021_A08_06_END

    return jsonify({"ok": True})


@bp.get("/plugin/import")
def a08_07_import_from_path():
    path = request.args.get("path", "")

    # GT:OWASP2021_A08_07_START
    loader = importlib.machinery.SourceFileLoader("plugin", path)  # untrusted plugin path
    mod = loader.load_module()
    # GT:OWASP2021_A08_07_END

    return jsonify({"ok": True, "module": str(mod)})


@bp.post("/pip/install")
def a08_08_pip_install_user_input():
    pkg = (request.json or {}).get("package", "")

    # GT:OWASP2021_A08_08_START
    subprocess.run(["python", "-m", "pip", "install", pkg], check=False)  # supply chain / integrity risk
    # GT:OWASP2021_A08_08_END

    return jsonify({"ok": True})


@bp.post("/signed/skip-verify")
def a08_09_skip_signature_verification():
    body = request.json or {}
    payload = body.get("payload", "")
    signature = body.get("signature", "")

    # GT:OWASP2021_A08_09_START
    # Integrity failure: signature provided but never verified.
    _ = (payload, signature)
    # GT:OWASP2021_A08_09_END

    return jsonify({"ok": True})


@bp.post("/update/apply")
def a08_10_apply_update_without_validation():
    patch = request.json or {}

    # GT:OWASP2021_A08_10_START
    # "Update" applied without validation, provenance, or integrity checks.
    with open("tmp/applied_update.json", "w", encoding="utf-8") as f:
        f.write(str(patch))
    # GT:OWASP2021_A08_10_END

    return jsonify({"ok": True})
