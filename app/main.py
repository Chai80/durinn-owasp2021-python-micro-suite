from flask import Flask, jsonify

from app.routes.health import bp as health_bp
from app.routes.a02 import bp as a02_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(health_bp, url_prefix="/health")
    app.register_blueprint(a02_bp, url_prefix="/a02")

    @app.get("/")
    def root():
        return jsonify({"service": "durinn-owasp2021-python-micro-suite", "ok": True, "scenario": "A02"})

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3000, debug=False)
