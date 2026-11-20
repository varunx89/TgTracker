"""Unit tests for cryptographic engine and security envelope."""

import os
from pathlib import Path
import pytest
from src.crypto import (
    generate_encryption_key,
    encrypt_session_string,
    decrypt_session_string,
    encode_envelope_b64,
    decode_envelope_b64,
    save_secure_file,
    read_secure_file,
    DecryptionTamperError,
    InsecurePermissionsError,
    verify_secure_permissions,
)


def test_generate_key():
    key = generate_encryption_key()
    assert isinstance(key, str)
    assert len(key) >= 43  # 32 bytes base64 encoded is 43-44 chars


def test_encrypt_decrypt_raw_key():
    key = generate_encryption_key()
    secret_session = "1BVtsOGQBu2V3dHj...telethon_mock_session_string..."
    
    envelope = encrypt_session_string(secret_session, key)
    assert envelope[0] == 0x01  # Raw key version
    
    decrypted = decrypt_session_string(envelope, key)
    assert decrypted == secret_session


def test_encrypt_decrypt_passphrase():
    passphrase = "Correct-Horse-Battery-Staple-Super-Secure-Passphrase!"
    secret_session = "1BVtsOGQBu2V3dHj...telethon_mock_session_string..."
    
    envelope = encrypt_session_string(secret_session, passphrase)
    assert envelope[0] == 0x02  # PBKDF2 version
    
    decrypted = decrypt_session_string(envelope, passphrase)
    assert decrypted == secret_session


def test_tamper_detection_ciphertext():
    key = generate_encryption_key()
    secret_session = "super-secret-telethon-string"
    envelope = bytearray(encrypt_session_string(secret_session, key))
    
    # Tamper with the last byte (authentication tag area)
    envelope[-1] ^= 0xFF
    
    with pytest.raises(DecryptionTamperError):
        decrypt_session_string(bytes(envelope), key)


def test_tamper_detection_wrong_key():
    key1 = generate_encryption_key()
    key2 = generate_encryption_key()
    secret_session = "super-secret-telethon-string"
    
    envelope = encrypt_session_string(secret_session, key1)
    
    with pytest.raises(DecryptionTamperError):
        decrypt_session_string(envelope, key2)


def test_tamper_detection_wrong_passphrase():
    passphrase1 = "PassphraseA"
    passphrase2 = "PassphraseB"
    secret_session = "super-secret-telethon-string"
    
    envelope = encrypt_session_string(secret_session, passphrase1)
    
    with pytest.raises(DecryptionTamperError):
        decrypt_session_string(envelope, passphrase2)


def test_base64_envelope_roundtrip():
    key = generate_encryption_key()
    secret_session = "super-secret-session"
    
    envelope = encrypt_session_string(secret_session, key)
    b64 = encode_envelope_b64(envelope)
    
    decoded_envelope = decode_envelope_b64(b64)
    assert decoded_envelope == envelope
    
    decrypted = decrypt_session_string(decoded_envelope, key)
    assert decrypted == secret_session


def test_secure_file_permissions(tmp_path: Path):
    file_path = tmp_path / "test_session.enc"
    data = b"confidential-data-content"
    
    save_secure_file(file_path, data)
    assert file_path.exists()
    
    mode = oct(file_path.stat().st_mode & 0o777)
    assert mode == "0o600", f"Expected 0o600, got {mode}"
    
    read_data = read_secure_file(file_path)
    assert read_data == data


def test_auto_repair_insecure_permissions(tmp_path: Path):
    file_path = tmp_path / "loose_session.enc"
    file_path.write_bytes(b"data")
    file_path.chmod(0o666)  # Insecure
    
    verify_secure_permissions(file_path)
    mode = oct(file_path.stat().st_mode & 0o777)
    assert mode == "0o600"
