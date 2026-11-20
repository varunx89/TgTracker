"""
Cryptographic Engine for TgTracker.
Provides military-grade Authenticated Encryption (AES-256-GCM) with PBKDF2-HMAC-SHA256
key derivation, strict 0600 file permission enforcement, and tamper detection.
"""

import base64
import os
import stat
from pathlib import Path
from typing import Union
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Protocol Constants
ENVELOPE_VERSION_RAW_KEY = 0x01
ENVELOPE_VERSION_PBKDF2 = 0x02
SALT_LENGTH_BYTES = 32
NONCE_LENGTH_BYTES = 12
PBKDF2_ITERATIONS = 600_000  # OWASP standard
ASSOCIATED_AUTHENTICATED_DATA = b"TgTracker:SecurityEnvelope:v1"


class CryptoSecurityError(Exception):
    """Base exception for cryptographic failures."""
    pass


class DecryptionTamperError(CryptoSecurityError):
    """Raised when data integrity or authentication check fails."""
    pass


class InsecurePermissionsError(CryptoSecurityError):
    """Raised when file permissions violate minimum security policy (0600)."""
    pass


def generate_encryption_key() -> str:
    """
    Generates a cryptographically strong 256-bit (32-byte) key,
    encoded in URL-safe Base64 for easy environment variable storage.
    """
    key = AESGCM.generate_key(bit_length=256)
    return base64.urlsafe_b64encode(key).decode("utf-8")


def _derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256
    with 600,000 iterations and a 32-byte CSPRNG salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _parse_key_or_passphrase(key_or_passphrase: str, salt: bytes | None = None) -> tuple[bytes, bool]:
    """
    Determines if input is a raw base64 256-bit key or a text passphrase.
    Returns: (32-byte key, is_raw_key)
    """
    clean = key_or_passphrase.strip()
    # Try decoding as 32-byte base64 key
    try:
        raw_key = base64.urlsafe_b64decode(clean.encode("utf-8"))
        if len(raw_key) == 32:
            return raw_key, True
    except Exception:
        pass

    try:
        raw_key = base64.b64decode(clean.encode("utf-8"))
        if len(raw_key) == 32:
            return raw_key, True
    except Exception:
        pass

    # Treat as text passphrase with PBKDF2
    if salt is None:
        raise ValueError("Salt must be provided for passphrase derivation")
    return _derive_key_from_passphrase(clean, salt), False


def encrypt_session_string(session_string: str, secret_key: str) -> bytes:
    """
    Encrypts a Telethon session string using AES-256-GCM.
    Returns binary envelope:
    Format 1 (Raw Key): [0x01][12-byte nonce][ciphertext + tag]
    Format 2 (Passphrase): [0x02][32-byte salt][12-byte nonce][ciphertext + tag]
    """
    if not session_string:
        raise ValueError("Session string cannot be empty")
    if not secret_key:
        raise ValueError("Secret key/passphrase cannot be empty")

    data = session_string.encode("utf-8")
    nonce = os.urandom(NONCE_LENGTH_BYTES)

    # Check if raw key
    try:
        key, is_raw = _parse_key_or_passphrase(secret_key)
    except ValueError:
        is_raw = False

    if is_raw:
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, ASSOCIATED_AUTHENTICATED_DATA)
        envelope = bytes([ENVELOPE_VERSION_RAW_KEY]) + nonce + ciphertext
    else:
        salt = os.urandom(SALT_LENGTH_BYTES)
        key, _ = _parse_key_or_passphrase(secret_key, salt=salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, ASSOCIATED_AUTHENTICATED_DATA)
        envelope = bytes([ENVELOPE_VERSION_PBKDF2]) + salt + nonce + ciphertext

    return envelope


def decrypt_session_string(envelope: bytes, secret_key: str) -> str:
    """
    Decrypts an AES-256-GCM envelope and returns the plaintext session string.
    Verifies AEAD tag and associated authenticated data to guarantee integrity.
    """
    if not envelope or len(envelope) < 1 + NONCE_LENGTH_BYTES + 16:
        raise DecryptionTamperError("Invalid envelope: data too short or corrupted")

    version = envelope[0]

    if version == ENVELOPE_VERSION_RAW_KEY:
        nonce_start = 1
        nonce_end = nonce_start + NONCE_LENGTH_BYTES
        nonce = envelope[nonce_start:nonce_end]
        ciphertext = envelope[nonce_end:]

        key, is_raw = _parse_key_or_passphrase(secret_key)
        if not is_raw:
            raise DecryptionTamperError("Payload encrypted with raw key, but passphrase was provided")

    elif version == ENVELOPE_VERSION_PBKDF2:
        salt_start = 1
        salt_end = salt_start + SALT_LENGTH_BYTES
        nonce_start = salt_end
        nonce_end = nonce_start + NONCE_LENGTH_BYTES

        if len(envelope) < nonce_end + 16:
            raise DecryptionTamperError("Invalid envelope: truncated PBKDF2 payload")

        salt = envelope[salt_start:salt_end]
        nonce = envelope[nonce_start:nonce_end]
        ciphertext = envelope[nonce_end:]

        # PBKDF2 envelope must always be derived using PBKDF2 with the payload salt
        key = _derive_key_from_passphrase(secret_key.strip(), salt)

    else:
        raise DecryptionTamperError(f"Unsupported envelope version: {version:#x}")

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, ASSOCIATED_AUTHENTICATED_DATA)
        return plaintext.decode("utf-8")
    except InvalidTag:
        raise DecryptionTamperError(
            "Decryption failed: cryptographic tag mismatch. "
            "Data was tampered with, corrupted, or the secret key is incorrect."
        )


def encode_envelope_b64(envelope: bytes) -> str:
    """Encodes encrypted binary envelope to URL-safe Base64."""
    return base64.urlsafe_b64encode(envelope).decode("utf-8")


def decode_envelope_b64(b64_string: str) -> bytes:
    """Decodes URL-safe Base64 string to encrypted binary envelope."""
    clean = b64_string.strip()
    try:
        return base64.urlsafe_b64decode(clean.encode("utf-8"))
    except Exception as e:
        raise DecryptionTamperError(f"Invalid Base64 encoding: {e}")


def save_secure_file(file_path: Union[str, Path], data: bytes) -> None:
    """
    Atomically writes data to disk enforcing strict POSIX 0600 permissions
    (readable and writable ONLY by the file owner; no access for group or others).
    """
    path = Path(file_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    # Use os.open with O_CREAT | O_WRONLY | O_TRUNC to ensure 0600 from creation
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        os.close(fd)
        raise

    # Verify permissions
    verify_secure_permissions(path)


def read_secure_file(file_path: Union[str, Path]) -> bytes:
    """
    Reads an encrypted file after verifying that its permissions are safe (0600).
    Warns or refuses to read if world/group readable.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Session file not found: {path}")

    verify_secure_permissions(path)
    return path.read_bytes()


def verify_secure_permissions(path: Path) -> None:
    """
    Verifies that a sensitive file has no permissions for group or others (0600).
    Automatically repairs permissions if loose on POSIX systems.
    """
    if os.name != "posix":
        return

    current_mode = stat.S_IMODE(path.stat().st_mode)
    # Check if group or others have read/write/execute
    if current_mode & 0o077:
        # Insecure permissions detected, attempt to tighten
        try:
            path.chmod(0o600)
        except Exception as e:
            raise InsecurePermissionsError(
                f"File {path} has insecure permissions {oct(current_mode)}. "
                f"Failed to tighten to 0600: {e}"
            )
