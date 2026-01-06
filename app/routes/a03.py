import os
import sqlite3
import subprocess

from flask import Blueprint, Response, jsonify, request, render_template_string

bp = Blueprint("a03", __name__)

COMMENTS = []

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);")
DB.execute("INSERT INTO users(name) VALUES ('alice'), ('bob'), ('carol');")
DB.commit()


@bp.get("/xss/reflected")
def a03_01_reflected_xss():
    msg = request.args.get("msg", "")

    # GT:OWASP2021_A03_01_START
    html = f"<h1>Echo</h1><div>{msg}</div>"  # unsanitized into HTML
    # GT:OWASP2021_A03_01_END

    return Response(html, mimetype="text/html")


@bp.post("/xss/store")
def a03_02_store_xss():
    comment = (request.json or {}).get("comment", "")
    COMMENTS.append(comment)
    return jsonify({"ok": True, "count": len(COMMENTS)})


@bp.get("/xss/view")
def a03_03_view_stored_xss():
    i = int(request.args.get("i", "0") or "0")
    comment = COMMENTS[i] if 0 <= i < len(COMMENTS) else ""

    # GT:OWASP2021_A03_03_START
    html = f"<p>Comment:</p><div>{comment}</div>"  # stored XSS
    # GT:OWASP2021_A03_03_END

    return Response(html, mimetype="text/html")


@bp.get("/sql/users")
def a03_04_sqli_concat():
    name = request.args.get("name", "")

    # GT:OWASP2021_A03_04_START
    sql = "SELECT id, name FROM users WHERE name = '" + name + "'"
    rows = list(DB.execute(sql))
    # GT:OWASP2021_A03_04_END

    return jsonify({"sql": sql, "rows": rows})


@bp.get("/sql/users2")
def a03_05_sqli_fstring():
    user_id = request.args.get("id", "1")

    # GT:OWASP2021_A03_05_START
    sql = f"SELECT id, name FROM users WHERE id = {user_id}"
    rows = list(DB.execute(sql))
    # GT:OWASP2021_A03_05_END

    return jsonify({"sql": sql, "rows": rows})


@bp.get("/cmd/os-system")
def a03_06_cmd_injection_os_system():
    arg = request.args.get("arg", "hello")

    # GT:OWASP2021_A03_06_START
    os.system("echo " + arg)  # command injection
    # GT:OWASP2021_A03_06_END

    return jsonify({"ok": True})


@bp.get("/cmd/subprocess-shell")
def a03_07_cmd_injection_subprocess_shell():
    arg = request.args.get("arg", "hello")

    # GT:OWASP2021_A03_07_START
    out = subprocess.check_output("echo " + arg, shell=True, text=True)  # command injection
    # GT:OWASP2021_A03_07_END

    return Response(out, mimetype="text/plain")


@bp.post("/template/render")
def a03_08_ssti_render_template_string():
    tpl = (request.json or {}).get("tpl", "")
    name = (request.json or {}).get("name", "world")

    # GT:OWASP2021_A03_08_START
    html = render_template_string(tpl, name=name)  # user-controlled template
    # GT:OWASP2021_A03_08_END

    return Response(html, mimetype="text/html")


@bp.get("/crlf")
def a03_09_crlf_header_injection():
    val = request.args.get("val", "")

    # GT:OWASP2021_A03_09_START
    resp = Response("ok", mimetype="text/plain")
    resp.headers["X-Note"] = val  # CRLF/header injection
    # GT:OWASP2021_A03_09_END

    return resp


@bp.get("/files/read")
def a03_10_path_traversal_read():
    path = request.args.get("path", "")

    try:
        # GT:OWASP2021_A03_10_START
        with open(path, "r", encoding="utf-8") as f:  # path traversal / arbitrary read
            data = f.read()
        # GT:OWASP2021_A03_10_END
        return Response(data[:500], mimetype="text/plain")
    except Exception as e:
        return jsonify({"error": "read_failed", "detail": str(e)}), 400


@bp.post("/eval")
def a03_11_eval_injection():
    code = (request.json or {}).get("code", "")

    # GT:OWASP2021_A03_11_START
    result = eval(code)  # code injection
    # GT:OWASP2021_A03_11_END

    return jsonify({"result": repr(result)})
