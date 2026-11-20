"""Unit tests for Security Guard and Chat Sandbox."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from telethon.tl.types import (
    PeerChannel,
    PeerChat,
    PeerUser,
    InputPeerSelf,
    InputUserSelf,
)
from src.security_guard import (
    canonicalize_chat_identifiers,
    is_peer_authorized,
    is_event_strictly_authorized,
    is_self_entity,
    apply_user_client_sandbox,
    apply_bot_client_sandbox,
    SecurityAccessDeniedError,
)


def test_canonicalize_chat_identifiers():
    # Supergroup / Channel with -100 prefix
    res = canonicalize_chat_identifiers(-1001234567890)
    assert -1001234567890 in res
    assert 1234567890 in res

    # Bare channel ID
    res2 = canonicalize_chat_identifiers(1234567890)
    assert 1234567890 in res2
    assert -1001234567890 in res2

    # Basic group
    res3 = canonicalize_chat_identifiers(-987654)
    assert -987654 in res3
    assert 987654 in res3


def test_is_peer_authorized():
    allowed = canonicalize_chat_identifiers(-1001999999999)

    # Authorized checks
    assert is_peer_authorized(-1001999999999, allowed) is True
    assert is_peer_authorized(1999999999, allowed) is True
    assert is_peer_authorized(PeerChannel(1999999999), allowed) is True

    # Unauthorized checks (DMs, other groups)
    assert is_peer_authorized(123456789, allowed) is False
    assert is_peer_authorized(-1001111111111, allowed) is False
    assert is_peer_authorized(PeerUser(55555), allowed) is False
    assert is_peer_authorized(PeerChat(44444), allowed) is False


def test_is_event_strictly_authorized():
    allowed = canonicalize_chat_identifiers(-1001999999999)

    # Valid event matching target
    valid_event = MagicMock()
    valid_event.chat_id = -1001999999999
    valid_event.message.peer_id = PeerChannel(1999999999)
    valid_event.message.chat_id = -1001999999999
    assert is_event_strictly_authorized(valid_event, allowed) is True

    # Event from personal DM / private chat
    dm_event = MagicMock()
    dm_event.chat_id = 99887766
    dm_event.message.peer_id = PeerUser(99887766)
    assert is_event_strictly_authorized(dm_event, allowed) is False

    # Event from another group
    other_group_event = MagicMock()
    other_group_event.chat_id = -1001234567890
    other_group_event.message.peer_id = PeerChannel(1234567890)
    assert is_event_strictly_authorized(other_group_event, allowed) is False


def test_user_client_sandbox_dialogs_blocked():
    async def _run():
        mock_client = MagicMock()
        apply_user_client_sandbox(mock_client, -1001999999999)

        with pytest.raises(SecurityAccessDeniedError, match="Listing dialogs"):
            await mock_client.get_dialogs()

        with pytest.raises(SecurityAccessDeniedError, match="Listing dialogs"):
            await mock_client.iter_dialogs()

    asyncio.run(_run())


def test_user_client_sandbox_write_prohibited():
    async def _run():
        mock_client = MagicMock()
        apply_user_client_sandbox(mock_client, -1001999999999)

        with pytest.raises(SecurityAccessDeniedError, match="strictly READ-ONLY"):
            await mock_client.send_message(-1001999999999, "Hello")

        with pytest.raises(SecurityAccessDeniedError, match="strictly READ-ONLY"):
            await mock_client.send_file(-1001999999999, b"bytes")

        with pytest.raises(SecurityAccessDeniedError, match="strictly READ-ONLY"):
            await mock_client.pin_message(-1001999999999, 123)

        with pytest.raises(SecurityAccessDeniedError, match="strictly READ-ONLY"):
            await mock_client.kick_participant(-1001999999999, 456)

    asyncio.run(_run())


def test_user_client_sandbox_unauthorized_chat_read():
    async def _run():
        mock_client = MagicMock()
        original_mock = AsyncMock(return_value=["mock_message"])
        mock_client.get_messages = original_mock
        apply_user_client_sandbox(mock_client, -1001999999999)

        # Allowed chat works
        res = await mock_client.get_messages(-1001999999999)
        assert res == ["mock_message"]
        assert original_mock.called

        # Unauthorized chat is blocked
        with pytest.raises(SecurityAccessDeniedError, match="unauthorized chat"):
            await mock_client.get_messages(-1001111111111)

    asyncio.run(_run())


def test_user_client_sandbox_participants_and_photos():
    async def _run():
        mock_client = MagicMock()
        mock_client.get_participants = AsyncMock(return_value=["user1"])
        mock_client.download_profile_photo = AsyncMock(return_value="photo.jpg")
        apply_user_client_sandbox(mock_client, -1001999999999)

        # Allowed chat participants works
        res = await mock_client.get_participants(-1001999999999)
        assert res == ["user1"]

        # Unauthorized chat participants is blocked
        with pytest.raises(SecurityAccessDeniedError, match="participants"):
            await mock_client.get_participants(-1001111111111)

        # Downloading photo for 'me' works
        assert await mock_client.download_profile_photo("me") == "photo.jpg"

        # Unauthorized profile photo download is blocked
        with pytest.raises(SecurityAccessDeniedError, match="unauthorized profile photos"):
            await mock_client.download_profile_photo(987654321)

    asyncio.run(_run())


def test_bot_client_sandbox_destination_restriction():
    async def _run():
        mock_client = MagicMock()
        orig_send_message = AsyncMock(return_value=MagicMock())
        orig_send_file = AsyncMock(return_value=MagicMock())
        mock_client.send_message = orig_send_message
        mock_client.send_file = orig_send_file
        apply_bot_client_sandbox(mock_client, -1002222222222)

        # Allowed destination chat succeeds
        await mock_client.send_message(-1002222222222, "Replicated Message")
        assert orig_send_message.called

        # Unauthorized destination is blocked
        with pytest.raises(SecurityAccessDeniedError, match="unauthorized peer"):
            await mock_client.send_message(-1003333333333, "Leak attempt")

        with pytest.raises(SecurityAccessDeniedError, match="unauthorized peer"):
            await mock_client.send_file(12345678, b"data")

    asyncio.run(_run())


def test_user_client_sandbox_self_entity_resolution():
    async def _run():
        mock_client = MagicMock()
        mock_client.get_entity = AsyncMock(return_value="self_entity")
        mock_client.get_input_entity = AsyncMock(return_value="input_self_entity")
        apply_user_client_sandbox(mock_client, -1001999999999)

        # 'me' and 'self' strings work
        assert await mock_client.get_entity("me") == "self_entity"
        assert await mock_client.get_input_entity("me") == "input_self_entity"

        # InputUserSelf() and InputPeerSelf() work
        input_user_self = InputUserSelf()
        input_peer_self = InputPeerSelf()
        assert await mock_client.get_input_entity(input_user_self) == "input_self_entity"
        assert await mock_client.get_input_entity(input_peer_self) == "input_self_entity"
        assert await mock_client.get_entity(input_user_self) == "self_entity"

        # Unauthorized entity is blocked
        with pytest.raises(SecurityAccessDeniedError, match="unauthorized"):
            await mock_client.get_input_entity(999888777)

    asyncio.run(_run())
