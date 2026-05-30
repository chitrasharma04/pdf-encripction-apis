# app.py — VaultPDF REST API
# ─────────────────────────────────────────────────────────────────────────────
# Production-ready Flask REST API wrapping the existing AES-256-CBC PDF
# encryption/decryption logic from utils/crypto.py.
#
# Keeps ALL original crypto code intact — only the interface changes from
# a server-rendered HTML app to a clean JSON REST API.
#
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────
#   GET    /health                   → liveness + stats
#   POST   /encrypt                  → encrypt a PDF upload
#   GET    /encrypt/files            → list encrypted files
#   DELETE /encrypt/files/<file_id>  → delete a file
#   POST   /decrypt/by-id            → decrypt by server file_id
#   POST   /decrypt                  → decrypt an uploaded .enc file directly
# ─────────────────────────────────────────────────────────────────────────────

import os
import secrets
import logging
from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import RequestEntityTooLarge

from routes import encrypt_bp, decrypt_bp, health_bp
from utils.helpers import configure_logging, error_response

# ─────────────────────────────────────────────────────────────────────────────
# Directory layout (all relative to this file)
# ─────────────────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent
UPLOAD_DIR     = BASE_DIR / "uploads"
LOG_DIR        = BASE_DIR / "logs"
METADATA_FILE  = UPLOAD_DIR / ".metadata.json"

# Create required directories on startup
(UPLOAD_DIR / "encrypted").mkdir(parents=True, exist_ok=True)
(UPLOAD_DIR / "decrypted").mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Logging — configure before the app so all modules inherit the handlers
# ─────────────────────────────────────────────────────────────────────────────
configure_logging(LOG_DIR)
logger = logging.getLogger("vaultpdf")


# ─────────────────────────────────────────────────────────────────────────────
# Flask application factory
# ─────────────────────────────────────────────────────────────────────────────

def create_app() -> Flask:
    """
    Application factory — create and configure the Flask app.

    Using a factory keeps the app testable: tests can call create_app()
    with different configs without importing a module-level `app` object.
    """
    app = Flask(__name__)

    # ── Core config ────────────────────────────────────────────────────────
    app.config.update(
        # Secret used by Flask for session signing — rotate in production via env var
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32)),

        # Global upload size cap: 50 MB (Werkzeug enforces this before the route runs)
        MAX_CONTENT_LENGTH=50 * 1024 * 1024,

        # Paths shared across blueprints via current_app.config
        BASE_DIR=str(BASE_DIR),
        UPLOAD_DIR=str(UPLOAD_DIR),
        METADATA_FILE=str(METADATA_FILE),
    )

    # ── CORS ───────────────────────────────────────────────────────────────
    # Allows any origin by default (good for local dev / Postman).
    # In production, restrict to your front-end origin:
    #   CORS(app, origins=["https://yourapp.com"])
    CORS(app, origins=os.environ.get("CORS_ORIGINS", "*"))

    # ── Register blueprints ────────────────────────────────────────────────
    # Each blueprint is a self-contained module with its own routes.
    app.register_blueprint(health_bp)          # GET  /health
    app.register_blueprint(encrypt_bp)         # POST /encrypt, GET/DELETE /encrypt/files
    app.register_blueprint(decrypt_bp)         # POST /decrypt, POST /decrypt/by-id

    # ── Global error handlers ──────────────────────────────────────────────

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(e):
        """Catch Werkzeug's 413 before it becomes an HTML error page."""
        return error_response("File exceeds the 50 MB size limit.", 413)

    @app.errorhandler(404)
    def handle_not_found(e):
        return error_response("Endpoint not found.", 404)

    @app.errorhandler(405)
    def handle_method_not_allowed(e):
        return error_response("HTTP method not allowed for this endpoint.", 405)

    @app.errorhandler(500)
    def handle_server_error(e):
        logger.exception("Unhandled 500 error: %s", e)
        return error_response("An unexpected server error occurred.", 500)

    # ── Root route — API index (useful when opened in a browser) ───────────
    @app.route("/", methods=["GET"])
    def api_index():
        return jsonify({
            "name":        "VaultPDF REST API",
            "version":     "1.0.0",
            "description": "AES-256-CBC PDF encryption/decryption service",
            "endpoints": {
                "health":          "GET  /health",
                "encrypt":         "POST /encrypt",
                "list_files":      "GET  /encrypt/files",
                "delete_file":     "DELETE /encrypt/files/<file_id>",
                "decrypt_by_id":   "POST /decrypt/by-id",
                "decrypt_upload":  "POST /decrypt",
            },
            "docs": "See README.md for full usage examples",
        }), 200

    logger.info("VaultPDF REST API initialised — upload dir: %s", UPLOAD_DIR)
    return app


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

app = create_app()   # module-level for gunicorn: `gunicorn app:app`

if __name__ == "__main__":
    print("=" * 60)
    print("  🔐 VaultPDF REST API")
    print("=" * 60)
    print(f"  Upload directory  : {UPLOAD_DIR}")
    print(f"  Log directory     : {LOG_DIR}")
    print(f"  Max upload size   : 50 MB")
    print(f"  Algorithm         : AES-256-CBC")
    print(f"  Key derivation    : PBKDF2-HMAC-SHA256 (260,000 iterations)")
    print("=" * 60)
    print("  Endpoints:")
    print("    GET    http://127.0.0.1:5000/health")
    print("    POST   http://127.0.0.1:5000/encrypt")
    print("    GET    http://127.0.0.1:5000/encrypt/files")
    print("    DELETE http://127.0.0.1:5000/encrypt/files/<file_id>")
    print("    POST   http://127.0.0.1:5000/decrypt/by-id")
    print("    POST   http://127.0.0.1:5000/decrypt")
    print("=" * 60)

    # debug=False for production; use gunicorn in real deployments
    app.run(debug=True, host="127.0.0.1", port=5000)
