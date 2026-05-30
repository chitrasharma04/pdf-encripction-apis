# utils/crypto.py
# Handles all AES-256 encryption and decryption logic for VaultPDF.
#
# Encryption format (.enc file layout):
#   [16 bytes: random IV]
#   [ 8 bytes: original file size, little-endian uint64]
#   [  N bytes: AES-256-CBC encrypted data, zero-padded to 16-byte boundary]

import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ── Constants ─────────────────────────────────────────────────────────────────
CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks
IV_SIZE    = 16          # AES IV is always 16 bytes
KEY_SIZE   = 32          # AES-256 uses a 32-byte (256-bit) key


# ── PKCS7 padding helpers ─────────────────────────────────────────────────────

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS7 padding so that len(data) is a multiple of block_size.

    PKCS7 appends N bytes each with value N, where N is the number of
    padding bytes needed (1–block_size).  A full padding block is added
    when the data is already aligned so that unpadding is unambiguous.

    Args:
        data:       The plaintext bytes to pad.
        block_size: AES block size (always 16 for AES-256).

    Returns:
        Padded bytes whose length is a multiple of block_size.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS7 padding from decrypted bytes.

    Validates that the padding is well-formed before removing it so that
    a corrupt or tampered ciphertext doesn't silently produce wrong output.

    Args:
        data:       Decrypted bytes (length must be a multiple of block_size).
        block_size: AES block size (always 16 for AES-256).

    Returns:
        Unpadded plaintext bytes.

    Raises:
        ValueError: If the padding is invalid (wrong value or length).
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data.")
    if len(data) % block_size != 0:
        raise ValueError(
            f"Data length ({len(data)}) is not a multiple of block size ({block_size})."
        )

    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError(f"Invalid PKCS7 padding byte: {pad_len}.")

    # Every padding byte must equal pad_len
    for byte in data[-pad_len:]:
        if byte != pad_len:
            raise ValueError("Invalid PKCS7 padding: padding bytes are not uniform.")

    return data[:-pad_len]


# ── Key utilities ─────────────────────────────────────────────────────────────

def generate_key() -> bytes:
    """Generate a cryptographically secure random 256-bit (32-byte) key."""
    return os.urandom(KEY_SIZE)


def load_or_create_key(key_path: str) -> bytes:
    """
    Load the server's master encryption key from disk.
    If the key file doesn't exist, generate a new one and save it.

    This key is used to encrypt ALL uploaded files on the server.

    SECURITY NOTE: In production, store this key in an environment variable
    or a secrets manager (AWS KMS, HashiCorp Vault, etc.), NOT on disk.
    """
    if os.path.exists(key_path):
        with open(key_path, 'rb') as f:
            key = f.read()
        if len(key) != KEY_SIZE:
            raise ValueError("Corrupted encryption key file (wrong length).")
        return key
    else:
        # First run: generate and persist a new key
        key = generate_key()
        with open(key_path, 'wb') as f:
            f.write(key)
        os.chmod(key_path, 0o600)   # owner read-only
        return key


# ── Core encrypt / decrypt ────────────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Encrypt a file using AES-256-CBC with a fresh random IV.

    .enc file format:
        [16 bytes: IV]
        [ 8 bytes: original file size, little-endian uint64]
        [  N bytes: encrypted payload, zero-padded to AES block boundary]

    The original file size is stored so decryption can trim null padding
    precisely without relying on PKCS7 (which would require buffering the
    entire last block before deciding how much to keep).

    Args:
        input_path:  Path to the plaintext PDF to encrypt.
        output_path: Path where the .enc file will be written.
        key:         32-byte AES-256 key.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes for AES-256. Got {len(key)}.")

    iv            = os.urandom(IV_SIZE)
    original_size = os.path.getsize(input_path)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        # Header: IV + original file size
        fout.write(iv)
        fout.write(struct.pack('<Q', original_size))

        # Stream encrypt in chunks; zero-pad the final chunk if needed
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break

            if len(chunk) % 16 != 0:
                # Pad with null bytes — original_size lets us trim on the way out
                padding_len = 16 - (len(chunk) % 16)
                chunk += b'\x00' * padding_len

            fout.write(encryptor.update(chunk))

        fout.write(encryptor.finalize())


def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    """
    Decrypt an AES-256-CBC .enc file and restore the original PDF.

    Reads the IV and original size from the file header, decrypts the
    payload in chunks, and trims null padding using the stored size so
    the output is byte-for-byte identical to the original PDF.

    Args:
        input_path:  Path to the .enc encrypted file.
        output_path: Path where the decrypted PDF will be written.
        key:         32-byte AES-256 key (must match the encryption key).

    Raises:
        ValueError:        If the .enc header is malformed.
        FileNotFoundError: If input_path does not exist.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes for AES-256. Got {len(key)}.")

    with open(input_path, 'rb') as fin:
        # ── Read header ──────────────────────────────────────────────────────
        iv = fin.read(IV_SIZE)
        if len(iv) != IV_SIZE:
            raise ValueError("Invalid .enc file: IV is missing or truncated.")

        size_bytes = fin.read(8)
        if len(size_bytes) != 8:
            raise ValueError("Invalid .enc file: original-size header is missing or truncated.")
        original_size = struct.unpack('<Q', size_bytes)[0]

        if original_size == 0:
            raise ValueError("Invalid .enc file: stored original size is 0.")

        # ── Decrypt ──────────────────────────────────────────────────────────
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        bytes_written = 0
        with open(output_path, 'wb') as fout:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break

                decrypted = decryptor.update(chunk)

                # Trim on last write to strip null padding precisely
                remaining = original_size - bytes_written
                if len(decrypted) >= remaining:
                    decrypted = decrypted[:remaining]

                fout.write(decrypted)
                bytes_written += len(decrypted)

            # Flush any internal buffering in the decryptor
            final_bytes = decryptor.finalize()
            remaining   = original_size - bytes_written
            if remaining > 0 and final_bytes:
                fout.write(final_bytes[:remaining])


def decrypt_bytes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt a raw AES-256-CBC ciphertext blob and remove PKCS7 padding.

    This is a convenience function for callers that already have the
    ciphertext in memory (e.g. unit tests, small in-memory payloads).
    For large files use decrypt_file() to avoid loading everything at once.

    Args:
        ciphertext: Encrypted bytes (must be a multiple of 16).
        key:        32-byte AES-256 key.
        iv:         16-byte initialisation vector.

    Returns:
        Decrypted plaintext bytes with PKCS7 padding removed.
    """
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)


def encrypt_bytes(plaintext: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Encrypt a plaintext blob with AES-256-CBC and PKCS7 padding.

    A convenience function for small in-memory payloads.  For large files
    use encrypt_file() to avoid loading everything at once.

    Args:
        plaintext: The bytes to encrypt.
        key:       32-byte AES-256 key.
        iv:        Optional 16-byte IV. A fresh random IV is generated if omitted.

    Returns:
        (ciphertext, iv) — the encrypted bytes and the IV used.
    """
    if iv is None:
        iv = os.urandom(IV_SIZE)
    padded    = pkcs7_pad(plaintext)
    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize(), iv
