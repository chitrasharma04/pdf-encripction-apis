# routes/health.py
import os
import logging
from pathlib import Path
from datetime import datetime

from flask import Blueprint, current_app

from utils.helpers import (
    load_metadata,
    human_readable_size,
    success_response,
    error_response,
)

health_bp = Blueprint("health", __name__)
logger    = logging.getLogger("vaultpdf.health")

_SERVER_START = datetime.now()


@health_bp.route("/health", methods=["GET"])
def health_check():
    upload_dir = Path(current_app.config["UPLOAD_DIR"])

    # Storage check
    try:
        storage_ok = upload_dir.exists() and os.access(str(upload_dir), os.W_OK)
    except Exception:
        storage_ok = False

    if not storage_ok:
        logger.error("Health check failed: storage not writable — %s", upload_dir)
        return error_response("Storage directory not accessible.", 503)

    metadata_file = Path(current_app.config["METADATA_FILE"])
    metadata      = load_metadata(metadata_file)

    total_files = len(metadata)
    total_bytes = sum(r.get("original_size", 0) for r in metadata.values())

    delta   = datetime.now() - _SERVER_START
    days    = delta.days
    hours   = delta.seconds // 3600
    minutes = (delta.seconds % 3600) // 60
    uptime  = f"{days}d {hours}h {minutes}m"

    return success_response(
        "VaultPDF API is running",
        data={
            "api_version":    "1.0.0",
            "encryption":     "AES-256-CBC",
            "key_derivation": "PBKDF2-HMAC-SHA256 (260,000 iterations)",
            "uptime":         uptime,
            "storage":        "accessible",
            "total_files":    total_files,
            "total_size":     human_readable_size(total_bytes),
            "timestamp":      datetime.now().isoformat(),
        },
    )
