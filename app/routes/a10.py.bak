import http.client
import socket
import urllib.parse
import urllib.request

import requests
from flask import Blueprint, Response, jsonify, request

bp = Blueprint("a10", __name__)


@bp.get("/fetch/requests")
def a10_01_requests_get():
    url = request.args.get("url", "")

    # GT:OWASP2021_A10_01_START
    r = requests.get(url, timeout=3)  # SSRF sink, no allowlist
    # GT:OWASP2021_A10_01_END

    return Response(r.text[:500], mimetype="text/plain")


@bp.get("/fetch/requests-redirects")
def a10_02_requests_redirects():
    url = request.args.get("url", "")

    # GT:OWASP2021_A10_02_START
    r = requests.get(url, timeout=3, allow_redirects=True)  # SSRF + redirects
    # GT:OWASP2021_A10_02_END

    return Response(r.text[:500], mimetype="text/plain")


@bp.post("/fetch/requests-post")
def a10_03_requests_post():
    url = (request.json or {}).get("url", "")
    data = (request.json or {}).get("data", {})

    # GT:OWASP2021_A10_03_START
    r = requests.post(url, json=data, timeout=3)  # SSRF sink
    # GT:OWASP2021_A10_03_END

    return jsonify({"status": r.status_code})


@bp.get("/fetch/urllib")
def a10_04_urllib_urlopen():
    url = request.args.get("url", "")

    # GT:OWASP2021_A10_04_START
    data = urllib.request.urlopen(url, timeout=3).read()  # SSRF sink
    # GT:OWASP2021_A10_04_END

    return Response(data[:500], mimetype="application/octet-stream")


@bp.get("/fetch/httpclient")
def a10_05_httpclient():
    url = request.args.get("url", "")
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 80
    path = parsed.path or "/"

    # GT:OWASP2021_A10_05_START
    conn = http.client.HTTPConnection(host, port, timeout=3)  # SSRF primitive
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read()
    # GT:OWASP2021_A10_05_END

    return Response(body[:500], mimetype="application/octet-stream")


@bp.get("/fetch/socket")
def a10_06_socket_connect():
    host = request.args.get("host", "")
    port = int(request.args.get("port", "80") or "80")

    # GT:OWASP2021_A10_06_START
    s = socket.create_connection((host, port), timeout=3)  # SSRF primitive
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    data = s.recv(512)
    s.close()
    # GT:OWASP2021_A10_06_END

    return Response(data, mimetype="application/octet-stream")


@bp.get("/fetch/metadata-default")
def a10_07_fetch_metadata_default():
    # GT:OWASP2021_A10_07_START
    url = request.args.get("url", "http://169.254.169.254/")  # defaults to metadata IP
    # GT:OWASP2021_A10_07_END
    r = requests.get(url, timeout=3)
    return Response(r.text[:500], mimetype="text/plain")


@bp.get("/proxy")
def a10_08_open_proxy():
    url = request.args.get("url", "")

    # GT:OWASP2021_A10_08_START
    r = requests.get(url, timeout=3)  # open proxy behavior
    # GT:OWASP2021_A10_08_END

    return Response(r.content[:500], mimetype=r.headers.get("Content-Type", "application/octet-stream"))


@bp.get("/fetch/head")
def a10_09_head_request():
    url = request.args.get("url", "")

    # GT:OWASP2021_A10_09_START
    r = requests.head(url, timeout=3)  # SSRF sink (HEAD)
    # GT:OWASP2021_A10_09_END

    return jsonify({"status": r.status_code, "headers": dict(r.headers)})


@bp.get("/fetch/stream")
def a10_10_stream_request():
    url = request.args.get("url", "")

    # GT:OWASP2021_A10_10_START
    r = requests.get(url, timeout=3, stream=True)  # SSRF sink
    # GT:OWASP2021_A10_10_END

    chunk = next(r.iter_content(chunk_size=256), b"")
    return Response(chunk, mimetype="application/octet-stream")
