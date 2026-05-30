# utils/helpers.py
# ─────────────────────────────────────────────────────────────────────────────
# Reusable helper/utility functions for VaultPDF REST API.
# Keeps app.py clean by isolating validation, formatting, metadata I/O, and
# response-building into one place.
# ─────────────────────────────────────────────────────────────────────────────

import os
import json
import uuid
import logging
from datetime import datetime
from pathlib import Path

from flask import jsonify
from werkzeug.datastructures import FileStorage

# ── Module-level logger ────────────────────────────────────────────────────────
logger = logging.getLogger("vaultpdf")

# ── Constants ──────────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {".pdf"}
ALLOWED_MIME_TYPES = {"application/pdf", "application/octet-stream"}
MAX_FILENAME_LENGTH = 255


# ─────────────────────────────────────────────────────────────────────────────
# File Validation
# ─────────────────────────────────────────────────────────────────────────────

def is_valid_pdf(file: FileStorage) -> tuple[bool, str]:
    """
    Validate an uploaded FileStorage object as a genuine PDF.

    Checks performed (in order):
      1. Filename is present and non-empty.
      2. File extension is '.pdf'.
      3. MIME type is acceptable (browser-reported; informational only).
      4. First 4 bytes match the PDF magic bytes: %PDF (0x25 50 44 46).

    Returns:
        (True, "")            on success.
        (False, reason_str)   on failure, with a human-readable reason.
    """
    if not file or not file.filename:
        return False, "No file or filename provided."

    filename = file.filename.strip()
    if len(filename) > MAX_FILENAME_LENGTH:
        return False, f"Filename exceeds {MAX_FILENAME_LENGTH} characters."

    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file type '{ext}'. Only .pdf files are accepted."

    # Magic-byte check — read just 4 bytes and reset the stream
    header = file.read(4)
    file.seek(0)
    if header != b"%PDF":
        return False, "File does not appear to be a valid PDF (bad magic bytes)."

    return True, ""


def validate_password(password: str | None) -> tuple[bool, str]:
    """
    Enforce basic password rules for user-supplied encryption passwords.

    Rules:
      • Must be present and non-empty after stripping whitespace.
      • At least 4 characters (generous lower bound; guides the API caller).
      • At most 128 characters (prevents absurdly long inputs).

    Returns:
        (True, "")           on success.
        (False, reason_str)  on failure.
    """
    if not password or not password.strip():
        return False, "Password is required and cannot be blank."
    p = password.strip()
    if len(p) < 4:
        return False, "Password must be at least 4 characters."
    if len(p) > 128:
        return False, "Password must not exceed 128 characters."
    return True, ""


def validate_uuid(value: str) -> bool:
    """Return True if *value* is a valid UUID4 string (prevents path traversal)."""
    try:
        uuid.UUID(str(value))
        return True
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Unique Filename Generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_unique_filename(original_name: str, suffix: str = ".enc") -> tuple[str, str]:
    """
    Generate a collision-safe filename based on a UUID4.

    Returns:
        (file_id, filename)
        e.g. ("3f7a2b1c-...", "3f7a2b1c-....enc")

    The original filename is stored in metadata only — never used as the
    on-disk name — so it cannot be used for path traversal.
    """
    file_id = str(uuid.uuid4())
    filename = f"{file_id}{suffix}"
    return file_id, filename


# ─────────────────────────────────────────────────────────────────────────────
# Human-Readable Sizes
# ─────────────────────────────────────────────────────────────────────────────

def human_readable_size(size_bytes: int) -> str:
    """Convert a byte count to a human-readable string (B / KB / MB / GB)."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.1f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} GB"


# ─────────────────────────────────────────────────────────────────────────────
# Metadata Persistence
# ─────────────────────────────────────────────────────────────────────────────

def load_metadata(metadata_file: Path) -> dict:
    """
    Load the file registry from *metadata_file*.
    Returns an empty dict if the file doesn't exist or is corrupt.
    """
    if not metadata_file.exists():
        return {}
    try:
        with open(metadata_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read metadata file: %s", exc)
        return {}


def save_metadata(data: dict, metadata_file: Path) -> None:
    """Persist the file registry to *metadata_file* atomically."""
    tmp_path = metadata_file.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, metadata_file)   # atomic on POSIX
    except OSError as exc:
        logger.error("Failed to save metadata: %s", exc)
        raise


def build_file_record(
    file_id: str,
    original_name: str,
    original_size: int,
    enc_filename: str,
    operation: str = "encrypt",
) -> dict:
    """
    Build a standardised metadata record for a processed file.

    Args:
        file_id:       UUID string.
        original_name: Original filename (sanitised before this call).
        original_size: Byte size of the original file.
        enc_filename:  Name of the stored .enc file on disk.
        operation:     "encrypt" or "decrypt" (informational).

    Returns:
        Dict ready to be stored in the metadata registry.
    """
    now = datetime.now()
    return {
        "id":               file_id,
        "original_name":    original_name,
        "original_size":    original_size,
        "readable_size":    human_readable_size(original_size),
        "enc_filename":     enc_filename,
        "operation":        operation,
        "created_at":       now.isoformat(),
        "created_at_fmt":   now.strftime("%b %d, %Y at %I:%M %p"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Standardised JSON Response Builders
# ─────────────────────────────────────────────────────────────────────────────

def success_response(message: str, data: dict | None = None, status_code: int = 200):
    """
    Return a Flask JSON response with a consistent success envelope.

    Shape:
    {
        "status":  "success",
        "message": "<message>",
        ...data fields merged at top level...
    }
    """
    payload = {"status": "success", "message": message}
    if data:
        payload.update(data)
    return jsonify(payload), status_code


def error_response(message: str, status_code: int = 400, details: str | None = None):
    """
    Return a Flask JSON response with a consistent error envelope.

    Shape:
    {
        "status":  "error",
        "message": "<message>",
        "details": "<optional extra info>"   ← only present when details != None
    }
    """
    payload: dict = {"status": "error", "message": message}
    if details:
        payload["details"] = details
    return jsonify(payload), status_code


# ─────────────────────────────────────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────────────────────────────────────

def configure_logging(log_dir: Path, level: int = logging.INFO) -> None:
    """
    Set up a dual-handler logger: console + rotating file.

    Call once at app startup.  All modules import the 'vaultpdf' logger and
    automatically inherit the handlers configured here.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "vaultpdf.log"

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(fmt)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)

    root = logging.getLogger("vaultpdf")
    root.setLevel(level)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)
    root.propagate = False
