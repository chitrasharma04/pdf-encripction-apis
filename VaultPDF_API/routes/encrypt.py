# routes/encrypt.py
# ─────────────────────────────────────────────────────────────────────────────
# Blueprint: /encrypt
#
# POST /encrypt
#   Accepts a PDF via multipart/form-data plus a user-supplied password.
#   Derives a per-file AES-256 key from the password + a random salt using
#   PBKDF2-HMAC-SHA256, then encrypts the PDF with the existing encrypt_file()
#   helper.  Stores the encrypted .enc file and returns JSON metadata.
#
# GET  /encrypt/files
#   Returns a list of all encrypted files in the registry.
#
# DELETE /encrypt/files/<file_id>
#   Deletes the specified encrypted file and its metadata record.
# ─────────────────────────────────────────────────────────────────────────────

import os
import logging
import tempfile
import hashlib

from pathlib import Path
from flask import Blueprint, request, current_app, after_this_request, send_file
from werkzeug.utils import secure_filename

from utils.crypto import encrypt_file, load_or_create_key
from utils.helpers import (
    is_valid_pdf,
    validate_password,
    validate_uuid,
    generate_unique_filename,
    human_readable_size,
    build_file_record,
    load_metadata,
    save_metadata,
    success_response,
    error_response,
)

# ── Blueprint registration ─────────────────────────────────────────────────────
encrypt_bp = Blueprint("encrypt", __name__, url_prefix="/encrypt")
logger = logging.getLogger("vaultpdf.encrypt")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES-256 key from a user password using PBKDF2-HMAC-SHA256.

    Using 260,000 iterations (OWASP 2023 minimum recommendation for PBKDF2-SHA256).
    The salt is stored alongside the encrypted file in metadata so it can be
    reproduced during decryption.

    Args:
        password:  Plain-text password supplied by the API caller.
        salt:      Random 32-byte salt (unique per file).

    Returns:
        32-byte derived key suitable for AES-256.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=260_000,
        dklen=32,
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /encrypt
# ─────────────────────────────────────────────────────────────────────────────

@encrypt_bp.route("", methods=["POST"])
def encrypt_pdf():
    """
    Encrypt an uploaded PDF with a user-supplied password.

    Request (multipart/form-data):
        file      — the PDF file to encrypt (required)
        password  — encryption password, 4–128 chars (required)

    Response 200:
        {
            "status":    "success",
            "message":   "PDF encrypted successfully",
            "file_id":   "<uuid>",
            "filename":  "original.pdf",
            "size":      "248.3 KB",
            "file":      "uploads/encrypted/<uuid>.enc",
            "created_at": "May 27, 2026 at 02:15 PM"
        }

    Error codes:
        400 — missing file / bad PDF / bad password
        413 — file too large (handled globally)
        500 — server-side encryption failure
    """
    # ── 1. Extract request parts ───────────────────────────────────────────
    if "file" not in request.files:
        return error_response("No file field in request. Use multipart/form-data with key 'file'.")

    file     = request.files["file"]
    password = request.form.get("password", "").strip()

    # ── 2. Validate file ───────────────────────────────────────────────────
    valid, reason = is_valid_pdf(file)
    if not valid:
        logger.warning("Rejected upload: %s", reason)
        return error_response(reason)

    # ── 3. Validate password ───────────────────────────────────────────────
    pwd_ok, pwd_reason = validate_password(password)
    if not pwd_ok:
        return error_response(pwd_reason)

    original_name = secure_filename(file.filename)

    # ── 4. Write upload to a temp file, then encrypt ───────────────────────
    tmp_path = None
    try:
        # Save the raw upload to a temp location (plaintext — deleted shortly)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            file.save(tmp.name)
            tmp_path     = tmp.name
            original_size = os.path.getsize(tmp_path)

        # Derive a per-file AES key from the user's password + fresh salt
        salt       = os.urandom(32)
        enc_key    = _derive_key_from_password(password, salt)

        # Generate a collision-safe output filename
        file_id, enc_filename = generate_unique_filename(original_name, suffix=".enc")
        enc_dir  = Path(current_app.config["UPLOAD_DIR"]) / "encrypted"
        enc_path = enc_dir / enc_filename
        enc_dir.mkdir(parents=True, exist_ok=True)

        # ── AES-256-CBC encryption (reusing existing crypto logic) ──────────
        encrypt_file(tmp_path, str(enc_path), enc_key)

        logger.info("Encrypted '%s' → %s (%s)", original_name, enc_filename,
                    human_readable_size(original_size))

    except Exception as exc:
        logger.exception("Encryption failed for '%s': %s", original_name, exc)
        return error_response("Encryption failed.", 500, details=str(exc))

    finally:
        # Always remove the plaintext temp file — never leave it on disk
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # ── 5. Persist metadata ────────────────────────────────────────────────
    metadata_file = Path(current_app.config["METADATA_FILE"])
    metadata      = load_metadata(metadata_file)

    record = build_file_record(file_id, original_name, original_size, enc_filename, "encrypt")
    # Store the salt (hex) so decryption can re-derive the same key
    record["salt_hex"] = salt.hex()

    metadata[file_id] = record
    save_metadata(metadata, metadata_file)

    # ── 6. Return success JSON ─────────────────────────────────────────────
    return success_response(
        "PDF encrypted successfully",
        data={
            "file_id":    file_id,
            "filename":   original_name,
            "size":       human_readable_size(original_size),
            "file":       f"uploads/encrypted/{enc_filename}",
            "created_at": record["created_at_fmt"],
            "salt_hex":   salt.hex(),   # save this if you plan to use POST /decrypt (file upload method)
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /encrypt/files  — list all encrypted files
# ─────────────────────────────────────────────────────────────────────────────

@encrypt_bp.route("/files", methods=["GET"])
def list_encrypted_files():
    """
    Return a JSON list of all encrypted files stored on the server.

    Response 200:
        {
            "status":  "success",
            "message": "X file(s) found",
            "count":   2,
            "files":   [ { ...record... }, ... ]
        }
    """
    metadata_file = Path(current_app.config["METADATA_FILE"])
    metadata      = load_metadata(metadata_file)

    # Filter to encrypt operations only; sort newest first
    files = [r for r in metadata.values() if r.get("operation") == "encrypt"]
    files.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    # Strip internal salt from the public response (security hygiene)
    public_files = [{k: v for k, v in f.items() if k != "salt_hex"} for f in files]

    return success_response(
        f"{len(public_files)} file(s) found",
        data={"count": len(public_files), "files": public_files},
    )


# ─────────────────────────────────────────────────────────────────────────────
# DELETE /encrypt/files/<file_id>
# ─────────────────────────────────────────────────────────────────────────────

@encrypt_bp.route("/files/<file_id>", methods=["DELETE"])
def delete_encrypted_file(file_id: str):
    """
    Delete an encrypted file and its metadata record.

    Path param:
        file_id — UUID of the file to delete

    Response 200:
        { "status": "success", "message": "File deleted successfully" }

    Error 400: invalid UUID
    Error 404: file not found in registry
    """
    if not validate_uuid(file_id):
        return error_response("Invalid file ID format.", 400)

    metadata_file = Path(current_app.config["METADATA_FILE"])
    metadata      = load_metadata(metadata_file)

    if file_id not in metadata:
        return error_response("File not found.", 404)

    record   = metadata[file_id]
    enc_path = Path(current_app.config["UPLOAD_DIR"]) / "encrypted" / record["enc_filename"]

    # Remove physical file (if it exists)
    if enc_path.exists():
        os.unlink(enc_path)
        logger.info("Deleted encrypted file: %s", enc_path.name)

    # Remove from registry
    del metadata[file_id]
    save_metadata(metadata, metadata_file)

    return success_response("File deleted successfully", data={"file_id": file_id})
