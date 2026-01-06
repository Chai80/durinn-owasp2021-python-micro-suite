from flask import Flask, jsonify, request

from app.routes.health import bp as health_bp
from app.routes.a05 import bp as a05_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # GT:OWASP2021_A05_CFG_01_START
    app.config["DEBUG"] = True  # debug enabled
    # GT:OWASP2021_A05_CFG_01_END

    # GT:OWASP2021_A05_CFG_02_START
    app.config["SECRET_KEY"] = "dev-secret-key"  # hardcoded/weak secret
    # GT:OWASP2021_A05_CFG_02_END

    # GT:OWASP2021_A05_CFG_03_START
    app.config["SESSION_COOKIE_SECURE"] = False
    # GT:OWASP2021_A05_CFG_03_END

    # GT:OWASP2021_A05_CFG_04_START
    app.config["SESSION_COOKIE_HTTPONLY"] = False
    # GT:OWASP2021_A05_CFG_04_END

    # GT:OWASP2021_A05_CFG_05_START
    app.config["SESSION_COOKIE_SAMESITE"] = None
    # GT:OWASP2021_A05_CFG_05_END

    app.register_blueprint(health_bp, url_prefix="/health")
    app.register_blueprint(a05_bp, url_prefix="/a05")

    @app.get("/")
    def root():
        return jsonify({"service": "durinn-owasp2021-python-micro-suite", "ok": True, "scenario": "A05"})

    @app.after_request
    def insecure_headers(resp):
        # GT:OWASP2021_A05_CFG_06_START
        resp.headers["Access-Control-Allow-Origin"] = "*"  # permissive CORS
        # GT:OWASP2021_A05_CFG_06_END

        # GT:OWASP2021_A05_CFG_07_START
        resp.headers["X-Frame-Options"] = "ALLOWALL"  # clickjacking allowed
        # GT:OWASP2021_A05_CFG_07_END

        # GT:OWASP2021_A05_CFG_08_START
        resp.headers["X-Content-Type-Options"] = "nosniff"  # (fine) included for comparison
        # GT:OWASP2021_A05_CFG_08_END

        return resp

    @app.errorhandler(Exception)
    def verbose_error_handler(err):
        # GT:OWASP2021_A05_CFG_09_START
        # Verbose errors in production leak internals.
        return jsonify({"error": str(err), "path": request.path}), 500
        # GT:OWASP2021_A05_CFG_09_END

    return app


app = create_app()

if __name__ == "__main__":
    # GT:OWASP2021_A05_CFG_10_START
    app.run(host="0.0.0.0", port=3000, debug=True)  # debug + bind all interfaces
    # GT:OWASP2021_A05_CFG_10_END
