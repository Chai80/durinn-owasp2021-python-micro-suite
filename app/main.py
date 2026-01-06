from flask import Flask, jsonify

from app.routes.health import bp as health_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.register_blueprint(health_bp, url_prefix="/health")

    @app.get("/")
    def root():
        return jsonify({"service": "durinn-owasp2021-python-micro-suite", "ok": True})

    return app


app = create_app()

if __name__ == "__main__":
    # baseline-clean: debug disabled
    app.run(host="127.0.0.1", port=3000, debug=False)
