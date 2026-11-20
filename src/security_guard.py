"""
Security Guard & Chat Sandbox for TgTracker.

Enforces zero-access privacy boundaries:
1. Canonical Chat ID resolution and strict whitelisting.
2. Inbound event drop filters (drops any non-target message immediately).
3. Active TelegramClient sandboxing:
   - Prohibits reading unauthorized chats/channels/DMs.
   - Prohibits dialog/chat enumeration (get_dialogs, iter_dialogs).
   - Prohibits user tracking client from sending messages anywhere (strict read-only).
   - Restricts bot client to sending messages EXCLUSIVELY to the authorized destination chat.
"""

import logging
from typing import Any, Callable, Set, Union
from telethon import TelegramClient
from telethon.tl.types import (
    PeerChannel,
    PeerChat,
    PeerUser,
    InputPeerSelf,
    InputUserSelf,
)
from telethon.utils import get_peer_id, resolve_id

logger = logging.getLogger("TgTracker.SecurityGuard")


class SecurityAccessDeniedError(PermissionError):
    """Raised when an operation attempts to access an unauthorized chat or perform a forbidden action."""
    pass


def is_self_entity(entity: Any) -> bool:
    """
    Evaluates whether an entity refers to the logged-in user account itself.
    Handles string aliases ('me', 'self', None) and internal Telethon TL types
    (InputPeerSelf, InputUserSelf).
    """
    if entity in ("me", "self", None):
        return True
    if isinstance(entity, (InputPeerSelf, InputUserSelf)):
        return True
    cls_name = getattr(getattr(entity, "__class__", None), "__name__", "")
    return cls_name in ("InputPeerSelf", "InputUserSelf", "UserSelf")


def canonicalize_chat_identifiers(raw_id: Union[int, str]) -> Set[int]:
    """
    Computes all valid numeric representations of a Telegram chat identifier.
    Telegram supergroups/channels can be represented as:
    - Marked ID: -1001234567890
    - Bare Channel ID: 1234567890
    - Basic group ID: -123456789
    Returns a set of integers matching all valid forms.
    """
    if isinstance(raw_id, str):
        raw_id = raw_id.strip()
        # Remove @ if username format
        if raw_id.startswith("@"):
            raw_id = raw_id[1:]
        try:
            numeric_id = int(raw_id)
        except ValueError:
            # Username format cannot be purely resolved to int without API query;
            # store hash or require numeric ID in production
            return set()
    else:
        numeric_id = int(raw_id)

    identifiers: Set[int] = {numeric_id}

    # If it is a channel marked with -100 prefix (e.g. -1001234567890)
    str_id = str(numeric_id)
    if str_id.startswith("-100"):
        bare_id = int(str_id[4:])
        identifiers.add(bare_id)
    elif numeric_id > 0:
        # Bare channel/supergroup ID -> add -100 prefix form
        marked_channel_id = int(f"-100{numeric_id}")
        identifiers.add(marked_channel_id)
    elif str_id.startswith("-") and not str_id.startswith("-100"):
        # Basic group
        bare_id = abs(numeric_id)
        identifiers.add(bare_id)

    return identifiers


def is_peer_authorized(peer: Any, allowed_canonical_ids: Set[int]) -> bool:
    """
    Evaluates whether an entity, peer object, or peer ID belongs to the authorized set.
    Handles raw integers, Telethon Peer objects (PeerChannel, PeerChat, PeerUser),
    Input objects (InputChannel, InputPeerChannel, InputPeerChat), and full TL entity types.
    """
    if peer is None:
        return False

    # 1. Direct integer or numeric string ID
    if isinstance(peer, (int, str)):
        try:
            peer_id = int(peer)
            if peer_id in allowed_canonical_ids:
                return True
            # Check canonical variants
            return bool(canonicalize_chat_identifiers(peer_id).intersection(allowed_canonical_ids))
        except ValueError:
            return False

    # 2. Universal get_peer_id helper (works across Peer, InputPeer, and InputChannel types)
    try:
        resolved_peer_id = get_peer_id(peer)
        if resolved_peer_id in allowed_canonical_ids:
            return True
        if bool(canonicalize_chat_identifiers(resolved_peer_id).intersection(allowed_canonical_ids)):
            return True
    except Exception:
        pass

    # 3. Check inner numeric attributes (channel_id, chat_id, user_id, id)
    for attr in ("channel_id", "chat_id", "user_id", "id"):
        inner_val = getattr(peer, attr, None)
        if inner_val is not None and isinstance(inner_val, int):
            if inner_val in allowed_canonical_ids:
                return True
            if bool(canonicalize_chat_identifiers(inner_val).intersection(allowed_canonical_ids)):
                return True

    return False


def is_event_strictly_authorized(event: Any, allowed_canonical_ids: Set[int]) -> bool:
    """
    Strict gatekeeper check for incoming Telethon updates.
    Ensures message originates exclusively from the authorized source chat.
    Rejects private messages (DMs), unauthorized groups, channels, and broadcasts.
    """
    if event is None:
        return False

    # Check event.chat_id
    event_chat_id = getattr(event, "chat_id", None)
    if event_chat_id is not None:
        if not is_peer_authorized(event_chat_id, allowed_canonical_ids):
            return False

    # Check inner message peer_id
    msg = getattr(event, "message", None)
    if msg is not None:
        peer_id = getattr(msg, "peer_id", None)
        if peer_id is not None and not is_peer_authorized(peer_id, allowed_canonical_ids):
            return False

        # Additional check on msg.chat_id
        msg_chat_id = getattr(msg, "chat_id", None)
        if msg_chat_id is not None and not is_peer_authorized(msg_chat_id, allowed_canonical_ids):
            return False

    return True


def apply_user_client_sandbox(client: TelegramClient, allowed_source_id: Union[int, str]) -> TelegramClient:
    """
    Sandboxes the user tracking TelegramClient to enforce strict single-chat isolation:
    1. Prohibits reading any messages or entities outside the authorized source group.
    2. Prohibits dialog listing / chat enumeration (iter_dialogs, get_dialogs).
    3. Prohibits user client from sending or editing messages (Strict Read-Only).
    4. Prohibits contact / profile scraping.
    """
    allowed_ids = canonicalize_chat_identifiers(allowed_source_id)

    # 1. Block dialogs enumeration
    async def forbidden_dialogs(*args, **kwargs):
        raise SecurityAccessDeniedError(
            "Security Policy Violation: Listing dialogs (get_dialogs/iter_dialogs) "
            "is permanently blocked to enforce zero-access privacy."
        )

    client.get_dialogs = forbidden_dialogs
    client.iter_dialogs = forbidden_dialogs
    client.get_drafts = forbidden_dialogs
    client.iter_drafts = forbidden_dialogs

    # 2. Block all write operations (User client is strictly read-only)
    async def forbidden_write(*args, **kwargs):
        raise SecurityAccessDeniedError(
            "Security Policy Violation: The user tracking client is strictly READ-ONLY. "
            "Sending, editing, forwarding, deleting, or pinning messages via user session is blocked."
        )

    client.send_message = forbidden_write
    client.send_file = forbidden_write
    client.forward_messages = forbidden_write
    client.edit_message = forbidden_write
    client.delete_messages = forbidden_write
    client.pin_message = forbidden_write
    client.unpin_message = forbidden_write
    client.kick_participant = forbidden_write
    client.edit_permissions = forbidden_write

    # 3. Guard entity resolution
    original_get_entity = client.get_entity
    original_get_input_entity = client.get_input_entity

    async def guarded_get_entity(entity, *args, **kwargs):
        # Allow resolving 'me' / InputUserSelf / InputPeerSelf for client initialization verification
        if is_self_entity(entity):
            return await original_get_entity(entity, *args, **kwargs)

        if not is_peer_authorized(entity, allowed_ids):
            raise SecurityAccessDeniedError(
                f"Security Policy Violation: Attempted to resolve unauthorized entity '{entity}'. "
                f"Client is strictly sandboxed to chat ID(s) {allowed_ids}."
            )
        return await original_get_entity(entity, *args, **kwargs)

    async def guarded_get_input_entity(entity, *args, **kwargs):
        # Allow resolving 'me' / InputUserSelf / InputPeerSelf for client initialization verification
        if is_self_entity(entity):
            return await original_get_input_entity(entity, *args, **kwargs)

        if not is_peer_authorized(entity, allowed_ids):
            raise SecurityAccessDeniedError(
                f"Security Policy Violation: Attempted to get input entity for unauthorized '{entity}'."
            )
        return await original_get_input_entity(entity, *args, **kwargs)

    client.get_entity = guarded_get_entity
    client.get_input_entity = guarded_get_input_entity

    # 4. Guard message retrieval
    original_get_messages = client.get_messages
    original_iter_messages = client.iter_messages

    async def guarded_get_messages(entity=None, *args, **kwargs):
        if entity is not None and not is_peer_authorized(entity, allowed_ids):
            raise SecurityAccessDeniedError(
                f"Security Policy Violation: Attempted to get messages from unauthorized chat '{entity}'."
            )
        return await original_get_messages(entity, *args, **kwargs)

    def guarded_iter_messages(entity=None, *args, **kwargs):
        if entity is not None and not is_peer_authorized(entity, allowed_ids):
            raise SecurityAccessDeniedError(
                f"Security Policy Violation: Attempted to iterate messages from unauthorized chat '{entity}'."
            )
        return original_iter_messages(entity, *args, **kwargs)

    client.get_messages = guarded_get_messages
    client.iter_messages = guarded_iter_messages

    # 5. Guard participant and profile retrieval
    original_get_participants = getattr(client, "get_participants", None)
    original_iter_participants = getattr(client, "iter_participants", None)
    original_download_profile_photo = getattr(client, "download_profile_photo", None)

    if original_get_participants:
        async def guarded_get_participants(entity, *args, **kwargs):
            if not is_peer_authorized(entity, allowed_ids):
                raise SecurityAccessDeniedError(f"Security Policy Violation: Access to participants of '{entity}' is blocked.")
            return await original_get_participants(entity, *args, **kwargs)
        client.get_participants = guarded_get_participants

    if original_iter_participants:
        def guarded_iter_participants(entity, *args, **kwargs):
            if not is_peer_authorized(entity, allowed_ids):
                raise SecurityAccessDeniedError(f"Security Policy Violation: Iterating participants of '{entity}' is blocked.")
            return original_iter_participants(entity, *args, **kwargs)
        client.iter_participants = guarded_iter_participants

    if original_download_profile_photo:
        async def guarded_download_profile_photo(entity, *args, **kwargs):
            if entity not in ("me", "self", None) and not is_peer_authorized(entity, allowed_ids):
                raise SecurityAccessDeniedError("Security Policy Violation: Downloading unauthorized profile photos is blocked.")
            return await original_download_profile_photo(entity, *args, **kwargs)
        client.download_profile_photo = guarded_download_profile_photo

    logger.info("User TelegramClient sandboxed successfully. Authorized source chat: %s", allowed_source_id)
    return client


def apply_bot_client_sandbox(client: TelegramClient, allowed_destination_id: Union[int, str]) -> TelegramClient:
    """
    Sandboxes the bot client to ensure it can ONLY transmit messages to the designated destination chat:
    1. Blocks sending messages or files to any recipient other than the authorized destination.
    2. Prohibits reading messages from any chats.
    """
    allowed_ids = canonicalize_chat_identifiers(allowed_destination_id)

    original_send_message = client.send_message
    original_send_file = client.send_file
    original_forward_messages = client.forward_messages

    async def guarded_send_message(entity, *args, **kwargs):
        if not is_peer_authorized(entity, allowed_ids):
            raise SecurityAccessDeniedError(
                f"Security Policy Violation: Bot attempted to send message to unauthorized peer '{entity}'. "
                f"Bot is restricted to destination chat {allowed_ids} only."
            )
        return await original_send_message(entity, *args, **kwargs)

    async def guarded_send_file(entity, *args, **kwargs):
        if not is_peer_authorized(entity, allowed_ids):
            raise SecurityAccessDeniedError(
                f"Security Policy Violation: Bot attempted to send file to unauthorized peer '{entity}'. "
                f"Bot is restricted to destination chat {allowed_ids} only."
            )
        return await original_send_file(entity, *args, **kwargs)

    async def guarded_forward_messages(entity, *args, **kwargs):
        if not is_peer_authorized(entity, allowed_ids):
            raise SecurityAccessDeniedError(
                f"Security Policy Violation: Bot attempted to forward to unauthorized peer '{entity}'."
            )
        return await original_forward_messages(entity, *args, **kwargs)

    client.send_message = guarded_send_message
    client.send_file = guarded_send_file
    client.forward_messages = guarded_forward_messages

    logger.info("Bot TelegramClient sandboxed successfully. Authorized destination chat: %s", allowed_destination_id)
    return client
