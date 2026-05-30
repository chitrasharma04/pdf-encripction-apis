# routes/decrypt.py
# ─────────────────────────────────────────────────────────────────────────────
# Blueprint: /decrypt
#
# POST /decrypt
#   Accepts an encrypted .enc file (or a file_id referencing a server-side
#   .enc file) plus the original password.  Re-derives the AES key, decrypts
#   the file on-the-fly, streams the PDF to the caller, then deletes the
#   temporary plaintext immediately.
#
# POST /decrypt/by-id
#   Same as above but the caller identifies the file by its registry UUID
#   instead of uploading the .enc file again.
# ─────────────────────────────────────────────────────────────────────────────

import os
import logging
import tempfile
import hashlib
import binascii

from pathlib import Path
from flask import Blueprint, request, current_app, after_this_request, send_file

from utils.crypto import decrypt_file
from utils.helpers import (
    is_valid_pdf,
    validate_password,
    validate_uuid,
    generate_unique_filename,
    human_readable_size,
    load_metadata,
    save_metadata,
    success_response,
    error_response,
)

# ── Blueprint registration ─────────────────────────────────────────────────────
decrypt_bp = Blueprint("decrypt", __name__, url_prefix="/decrypt")
logger = logging.getLogger("vaultpdf.decrypt")


# ─────────────────────────────────────────────────────────────────────────────
# Internal: re-derive AES key from stored salt + supplied password
# ─────────────────────────────────────────────────────────────────────────────

def _derive_key_from_record(password: str, record: dict) -> bytes:
    """
    Re-derive the AES-256 key using the salt stored in the metadata record.

    This must mirror the derivation in routes/encrypt.py exactly:
      PBKDF2-HMAC-SHA256, 260,000 iterations, dklen=32.

    Args:
        password: Plain-text password supplied by the API caller.
        record:   Metadata dict for the file (must contain 'salt_hex').

    Returns:
        32-byte AES key.

    Raises:
        KeyError:  if 'salt_hex' is absent from the record.
        ValueError: if the hex string is malformed.
    """
    salt = bytes.fromhex(record["salt_hex"])
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=260_000,
        dklen=32,
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /decrypt/by-id  — decrypt a server-stored file by its UUID
# ─────────────────────────────────────────────────────────────────────────────

@decrypt_bp.route("/by-id", methods=["POST"])
def decrypt_by_id():
    """
    Decrypt a previously encrypted file using its server-side UUID.

    Request (application/json  OR  multipart/form-data):
        file_id   — UUID returned by POST /encrypt  (required)
        password  — the password used during encryption  (required)

    On success: streams the decrypted PDF as an attachment.
    On failure: returns a JSON error response.

    The decrypted temp file is deleted from disk immediately after the
    response is sent — it never persists longer than the HTTP transaction.
    """
    # Support both JSON body and form data
    if request.is_json:
        body     = request.get_json(silent=True) or {}
        file_id  = body.get("file_id", "").strip()
        password = body.get("password", "").strip()
    else:
        file_id  = request.form.get("file_id", "").strip()
        password = request.form.get("password", "").strip()

    # ── Validate inputs ────────────────────────────────────────────────────
    if not file_id:
        return error_response("'file_id' is required.")

    if not validate_uuid(file_id):
        return error_response("Invalid file_id format (expected UUID).", 400)

    pwd_ok, pwd_reason = validate_password(password)
    if not pwd_ok:
        return error_response(pwd_reason)

    # ── Look up metadata ───────────────────────────────────────────────────
    metadata_file = Path(current_app.config["METADATA_FILE"])
    metadata      = load_metadata(metadata_file)

    if file_id not in metadata:
        return error_response("File not found. It may have been deleted.", 404)

    record   = metadata[file_id]
    enc_path = Path(current_app.config["UPLOAD_DIR"]) / "encrypted" / record["enc_filename"]

    if not enc_path.exists():
        return error_response("Encrypted file missing from storage.", 404)

    # ── Re-derive AES key ──────────────────────────────────────────────────
    try:
        enc_key = _derive_key_from_record(password, record)
    except (KeyError, ValueError) as exc:
        logger.error("Key derivation failed for file_id=%s: %s", file_id, exc)
        return error_response("Cannot derive encryption key from stored metadata.", 500)

    # ── Decrypt to temp file ───────────────────────────────────────────────
    tmp_decrypted = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp_decrypted.close()

    try:
        decrypt_file(str(enc_path), tmp_decrypted.name, enc_key)
        logger.info("Decrypted '%s' for download (file_id=%s)", record["original_name"], file_id)
    except Exception as exc:
        os.unlink(tmp_decrypted.name)
        logger.warning(
            "Decryption failed for file_id=%s — likely wrong password. %s", file_id, exc
        )
        return error_response(
            "Decryption failed. Please check your password and try again.",
            400,
            details=str(exc),
        )

    # ── Clean up temp file after response is sent ──────────────────────────
    @after_this_request
    def _cleanup(response):
        try:
            if os.path.exists(tmp_decrypted.name):
                os.unlink(tmp_decrypted.name)
        except Exception:
            pass
        return response

    # ── Stream the decrypted PDF ───────────────────────────────────────────
    return send_file(
        tmp_decrypted.name,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=record["original_name"],
    )


# ─────────────────────────────────────────────────────────────────────────────
# POST /decrypt  — decrypt an uploaded .enc file directly
# ─────────────────────────────────────────────────────────────────────────────

@decrypt_bp.route("", methods=["POST"])
def decrypt_uploaded_file():
    """
    Decrypt an .enc file uploaded directly in the request.

    Use this endpoint when the caller holds the .enc file locally (i.e. they
    downloaded it earlier and want to decrypt it without storing it on the
    server again).

    Request (multipart/form-data):
        file      — the .enc file to decrypt  (required)
        password  — the original encryption password  (required)
        salt_hex  — the hex-encoded salt returned by POST /encrypt  (required)

    On success: streams the decrypted PDF as an attachment.
    On failure: returns a JSON error response.
    """
    if "file" not in request.files:
        return error_response("No file field found. Use multipart/form-data with key 'file'.")

    enc_file  = request.files["file"]
    password  = request.form.get("password", "").strip()
    salt_hex  = request.form.get("salt_hex", "").strip()

    # ── Validate password ──────────────────────────────────────────────────
    pwd_ok, pwd_reason = validate_password(password)
    if not pwd_ok:
        return error_response(pwd_reason)

    # ── Validate salt ──────────────────────────────────────────────────────
    if not salt_hex:
        return error_response("'salt_hex' is required to re-derive the encryption key.")
    try:
        salt = bytes.fromhex(salt_hex)
        if len(salt) != 32:
            raise ValueError("Salt must be 32 bytes (64 hex chars).")
    except (ValueError, binascii.Error) as exc:
        return error_response(f"Invalid salt_hex: {exc}", 400)

    # ── Derive key from password + salt ────────────────────────────────────
    enc_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=260_000,
        dklen=32,
    )

    # ── Save uploaded .enc to temp, then decrypt ───────────────────────────
    tmp_enc      = None
    tmp_dec_path = None

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp:
            enc_file.save(tmp.name)
            tmp_enc = tmp.name

        tmp_dec = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        tmp_dec.close()
        tmp_dec_path = tmp_dec.name

        decrypt_file(tmp_enc, tmp_dec_path, enc_key)
        logger.info("Decrypted uploaded .enc file '%s'", enc_file.filename)

    except Exception as exc:
        if tmp_dec_path and os.path.exists(tmp_dec_path):
            os.unlink(tmp_dec_path)
        logger.warning("Decryption of uploaded .enc failed: %s", exc)
        return error_response(
            "Decryption failed. Please check your password and salt and try again.",
            400,
            details=str(exc),
        )
    finally:
        if tmp_enc and os.path.exists(tmp_enc):
            os.unlink(tmp_enc)

    # ── Clean up decrypted temp after response ─────────────────────────────
    @after_this_request
    def _cleanup(response):
        try:
            if tmp_dec_path and os.path.exists(tmp_dec_path):
                os.unlink(tmp_dec_path)
        except Exception:
            pass
        return response

    download_name = Path(enc_file.filename).stem + ".pdf" if enc_file.filename else "decrypted.pdf"

    return send_file(
        tmp_dec_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=download_name,
    )
