"""Unit tests for TrackerService lifecycle, decryption, and sandboxing."""

import asyncio
import base64
import ipaddress
import struct
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from telethon.sessions.string import CURRENT_VERSION
from src.config import TrackerConfig
from src.crypto import (
    encrypt_session_string,
    generate_encryption_key,
    save_secure_file,
    encode_envelope_b64,
)
from src.tracker_service import TrackerService


def _generate_valid_mock_session_string() -> str:
    """Generates a structurally valid Telethon StringSession for testing."""
    dc_id = 2
    ip = ipaddress.IPv4Address("149.154.167.50").packed
    port = 443
    auth_key = b"\x00" * 256
    data = struct.pack(">B4sH256s", dc_id, ip, port, auth_key)
    return CURRENT_VERSION + base64.urlsafe_b64encode(data).decode("ascii")


def test_decrypt_session_from_file(tmp_path):
    key = generate_encryption_key()
    session_file = tmp_path / "test_session.enc"
    raw_session = _generate_valid_mock_session_string()
    envelope = encrypt_session_string(raw_session, key)
    save_secure_file(session_file, envelope)

    cfg = TrackerConfig(
        telegram_api_id=1234567,
        telegram_api_hash="0123456789abcdef0123456789abcdef",
        telegram_bot_token="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456",
        source_track_chat_id=-1001111111111,
        destination_receive_chat_id=-1002222222222,
        session_storage_mode="file",
        session_encryption_key=key,
        encrypted_session_file=str(session_file),
    )

    service = TrackerService(cfg)
    decrypted = service._decrypt_session()
    assert decrypted == raw_session


def test_decrypt_session_from_env_string():
    key = generate_encryption_key()
    raw_session = _generate_valid_mock_session_string()
    envelope = encrypt_session_string(raw_session, key)
    b64_env = encode_envelope_b64(envelope)

    cfg = TrackerConfig(
        telegram_api_id=1234567,
        telegram_api_hash="0123456789abcdef0123456789abcdef",
        telegram_bot_token="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456",
        source_track_chat_id=-1001111111111,
        destination_receive_chat_id=-1002222222222,
        session_storage_mode="env_string",
        session_encryption_key=key,
        encrypted_session_string=b64_env,
    )

    service = TrackerService(cfg)
    decrypted = service._decrypt_session()
    assert decrypted == raw_session


def test_service_start_and_shutdown(tmp_path):
    async def _run():
        key = generate_encryption_key()
        session_file = tmp_path / "session.enc"
        raw_session = _generate_valid_mock_session_string()
        save_secure_file(session_file, encrypt_session_string(raw_session, key))

        cfg = TrackerConfig(
            telegram_api_id=1234567,
            telegram_api_hash="0123456789abcdef0123456789abcdef",
            telegram_bot_token="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456",
            source_track_chat_id=-1001111111111,
            destination_receive_chat_id=-1002222222222,
            session_storage_mode="file",
            session_encryption_key=key,
            encrypted_session_file=str(session_file),
        )

        service = TrackerService(cfg)

        # Mock TelegramClient
        mock_user = MagicMock()
        mock_user.connect = AsyncMock()
        mock_user.is_user_authorized = AsyncMock(return_value=True)
        mock_user.get_me = AsyncMock(return_value=MagicMock(first_name="TrackAccount", id=99999))
        mock_user.get_entity = AsyncMock(return_value=MagicMock(title="Source Group"))
        mock_user.on = MagicMock(return_value=lambda f: f)
        mock_user.is_connected = MagicMock(return_value=True)
        mock_user.disconnect = AsyncMock()

        mock_bot = MagicMock()
        mock_bot.start = AsyncMock()
        mock_bot.get_me = AsyncMock(return_value=MagicMock(username="ForwardBot", id=88888))
        mock_bot.is_connected = MagicMock(return_value=True)
        mock_bot.disconnect = AsyncMock()

        with patch("src.tracker_service.TelegramClient", side_effect=[mock_user, mock_bot]):
            await service.start()
            assert service._running is True
            assert service.user_client is mock_user
            assert service.bot_client is mock_bot

            service.stop()
            assert service._running is False

            await service.cleanup()
            mock_user.disconnect.assert_called_once()
            mock_bot.disconnect.assert_called_once()

    asyncio.run(_run())
