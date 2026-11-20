"""Unit tests for configuration validation and security redaction."""

import pytest
from pydantic import ValidationError
from src.config import TrackerConfig


def test_valid_config():
    cfg = TrackerConfig(
        telegram_api_id=1234567,
        telegram_api_hash="0123456789abcdef0123456789abcdef",
        telegram_bot_token="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456",
        source_track_chat_id=-1001111111111,
        destination_receive_chat_id=-1002222222222,
        session_encryption_key="super-secret-key-phrase-1234",
    )
    assert cfg.telegram_api_id == 1234567
    assert cfg.source_track_chat_id == -1001111111111
    assert cfg.destination_receive_chat_id == -1002222222222
    assert cfg.replicate_media is True


def test_identical_source_and_destination_fails():
    with pytest.raises(ValidationError, match="cannot be identical"):
        TrackerConfig(
            telegram_api_id=1234567,
            telegram_api_hash="0123456789abcdef0123456789abcdef",
            telegram_bot_token="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456",
            source_track_chat_id=-1001111111111,
            destination_receive_chat_id=-1001111111111,
            session_encryption_key="valid_secret_length_12345",
        )


def test_invalid_api_hash_length():
    with pytest.raises(ValidationError, match="32-character hexadecimal string"):
        TrackerConfig(
            telegram_api_id=1234567,
            telegram_api_hash="short_hash_longer_than_16_but_not_32",
            telegram_bot_token="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456",
            source_track_chat_id=-1001111111111,
            destination_receive_chat_id=-1002222222222,
            session_encryption_key="valid_secret_length_12345",
        )


def test_invalid_bot_token_format():
    with pytest.raises(ValidationError, match="Invalid bot token format"):
        TrackerConfig(
            telegram_api_id=1234567,
            telegram_api_hash="0123456789abcdef0123456789abcdef",
            telegram_bot_token="invalid_token_without_colon_long_enough",
            source_track_chat_id=-1001111111111,
            destination_receive_chat_id=-1002222222222,
            session_encryption_key="valid_secret_length_12345",
        )


def test_env_string_mode_requires_string():
    with pytest.raises(ValidationError, match="ENCRYPTED_SESSION_STRING is not set"):
        TrackerConfig(
            telegram_api_id=1234567,
            telegram_api_hash="0123456789abcdef0123456789abcdef",
            telegram_bot_token="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456",
            source_track_chat_id=-1001111111111,
            destination_receive_chat_id=-1002222222222,
            session_storage_mode="env_string",
            session_encryption_key="valid_secret_length_12345",
            encrypted_session_string=None,
        )


def test_secrets_redacted_in_repr():
    cfg = TrackerConfig(
        telegram_api_id=1234567,
        telegram_api_hash="0123456789abcdef0123456789abcdef",
        telegram_bot_token="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456",
        source_track_chat_id=-1001111111111,
        destination_receive_chat_id=-1002222222222,
        session_encryption_key="super-sensitive-passphrase",
    )
    repr_str = repr(cfg)
    assert "0123456789abcdef0123456789abcdef" not in repr_str
    assert "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456" not in repr_str
    assert "super-sensitive-passphrase" not in repr_str
    assert "api_hash=***" in repr_str
    assert "bot_token=***" in repr_str
    assert "secret_key=***" in repr_str
