"""
Zero-Disk Message Replicator for TgTracker.

Replicates messages from the tracked source group to the destination group via the bot client:
- High-fidelity visual formatting (bold, italic, code, quotes, spoilers, links).
- RAM-only media transmission (BytesIO). Never touches disk or temporary files.
- Strict zero-storage policy: messages, texts, and media are never persisted.
- Preserves reply threading using in-memory integer-only ID mapping.
- Memory scrubbing after each transmission.
"""

import io
import logging
from collections import OrderedDict
from typing import Any, Optional
from telethon import TelegramClient
from telethon.tl.types import (
    MessageMediaContact,
    MessageMediaDocument,
    MessageMediaGeo,
    MessageMediaPhoto,
    MessageMediaPoll,
    MessageMediaVenue,
)

logger = logging.getLogger("TgTracker.Replicator")

MAX_REPLY_CACHE_SIZE = 1000


class MessageReplicator:
    """
    Handles zero-disk replication of Telegram messages between user client and bot client.
    """

    def __init__(
        self,
        bot_client: TelegramClient,
        destination_chat_id: int,
        replicate_media: bool = True,
        max_media_size_mb: int = 50,
        preserve_replies: bool = True,
    ):
        self.bot_client = bot_client
        self.destination_chat_id = destination_chat_id
        self.replicate_media = replicate_media
        self.max_media_size_bytes = max_media_size_mb * 1024 * 1024
        self.preserve_replies = preserve_replies
        # LRU cache mapping source_message_id -> destination_message_id (integers only)
        self._reply_map: OrderedDict[int, int] = OrderedDict()

    def _record_reply_mapping(self, source_id: int, dest_id: int) -> None:
        """Records source -> destination message ID mapping with strict LRU eviction."""
        if not self.preserve_replies:
            return
        self._reply_map[source_id] = dest_id
        if len(self._reply_map) > MAX_REPLY_CACHE_SIZE:
            self._reply_map.popitem(last=False)

    def _get_destination_reply_id(self, source_reply_id: Optional[int]) -> Optional[int]:
        """Resolves source reply ID to corresponding destination message ID."""
        if not self.preserve_replies or source_reply_id is None:
            return None
        return self._reply_map.get(source_reply_id)

    async def replicate(self, message: Any, user_client: TelegramClient) -> None:
        """
        Replicates a message from the source group to the destination group.
        Guarantees zero persistent storage and immediate memory cleanup.
        """
        if message is None:
            return

        source_msg_id = getattr(message, "id", None)
        source_reply_to_id = getattr(message, "reply_to_msg_id", None)
        dest_reply_id = self._get_destination_reply_id(source_reply_to_id)

        try:
            # 1. Media handling
            if message.media and self.replicate_media:
                await self._replicate_media_message(message, user_client, dest_reply_id)
            # 2. Text-only message
            elif message.text or message.message:
                await self._replicate_text_message(message, dest_reply_id)
            else:
                # Other unsupported or empty message types
                logger.debug("Skipped empty or unsupported message type for ID: %s", source_msg_id)

        except Exception as e:
            logger.error("Error replicating message ID %s: %s", source_msg_id, type(e).__name__)
        finally:
            # Explicit memory hygiene
            del message

    async def _replicate_text_message(self, message: Any, reply_to_id: Optional[int]) -> None:
        """Replicates text message preserving entities and reply threading."""
        sent = await self.bot_client.send_message(
            entity=self.destination_chat_id,
            message=message.message or message.text,
            formatting_entities=message.entities,
            link_preview=bool(getattr(message, "web_preview", False)),
            reply_to=reply_to_id,
        )
        if sent and hasattr(sent, "id"):
            self._record_reply_mapping(message.id, sent.id)
            logger.info("Successfully replicated text message [Source ID: %s -> Dest ID: %s]", message.id, sent.id)

    async def _replicate_media_message(
        self,
        message: Any,
        user_client: TelegramClient,
        reply_to_id: Optional[int],
    ) -> None:
        """Streams media directly through in-memory BytesIO buffer without touching disk."""
        media = message.media

        # Handle Telegram Polls
        if isinstance(media, MessageMediaPoll):
            await self._replicate_poll(message, reply_to_id)
            return

        # Handle Location / Geo
        if isinstance(media, (MessageMediaGeo, MessageMediaVenue)):
            await self._replicate_geo(message, reply_to_id)
            return

        # Handle Contact
        if isinstance(media, MessageMediaContact):
            await self._replicate_contact(message, reply_to_id)
            return

        # Handle standard binary media: Photos, Documents, Audio, Video, Stickers
        file_size = getattr(message.file, "size", 0) if hasattr(message, "file") and message.file else 0

        # Memory overload protection check
        if file_size > self.max_media_size_bytes:
            logger.warning(
                "Media size %s bytes exceeds RAM safety limit %s bytes for message ID %s. "
                "Sending placeholder to protect server memory.",
                file_size, self.max_media_size_bytes, message.id
            )
            notice = f"⚠️ [TgTracker Notice]: An attachment exceeded the in-memory size threshold ({self.max_media_size_bytes // (1024*1024)} MB) and was skipped to protect system RAM."
            if message.text:
                notice = f"{message.text}\n\n{notice}"
            await self.bot_client.send_message(
                entity=self.destination_chat_id,
                message=notice,
                reply_to=reply_to_id,
            )
            return

        # In-memory stream buffer
        buffer = io.BytesIO()
        try:
            # Download directly into RAM
            await user_client.download_media(message, file=buffer)
            buffer.seek(0)

            # Assign file metadata
            file_name = getattr(message.file, "name", None) or "file"
            buffer.name = file_name

            is_voice = bool(getattr(message, "voice", False))
            is_video_note = bool(getattr(message, "video_note", False))

            caption_text = message.message or message.text or None
            caption_entities = message.entities if caption_text else None

            sent = await self.bot_client.send_file(
                entity=self.destination_chat_id,
                file=buffer,
                caption=caption_text,
                formatting_entities=caption_entities,
                voice_note=is_voice,
                video_note=is_video_note,
                reply_to=reply_to_id,
                attributes=getattr(message.document, "attributes", None) if hasattr(message, "document") and message.document else None,
            )

            if sent and hasattr(sent, "id"):
                self._record_reply_mapping(message.id, sent.id)
                logger.info("Successfully replicated media message [Source ID: %s -> Dest ID: %s]", message.id, sent.id)

        finally:
            # Zero and wipe the in-memory buffer immediately
            buffer.seek(0)
            buffer.truncate(0)
            buffer.close()
            del buffer

    async def _replicate_poll(self, message: Any, reply_to_id: Optional[int]) -> None:
        """Replicates poll structure."""
        poll_media = message.media.poll
        question = getattr(poll_media, "question", "Poll")
        answers = [getattr(ans, "text", str(ans)) for ans in getattr(poll_media, "answers", [])]
        
        # Present poll cleanly via bot
        lines = [f"📊 **Poll: {question}**\n"]
        for i, ans in enumerate(answers, 1):
            lines.append(f"{i}. {ans}")
        poll_text = "\n".join(lines)

        sent = await self.bot_client.send_message(
            entity=self.destination_chat_id,
            message=poll_text,
            reply_to=reply_to_id,
        )
        if sent and hasattr(sent, "id"):
            self._record_reply_mapping(message.id, sent.id)

    async def _replicate_geo(self, message: Any, reply_to_id: Optional[int]) -> None:
        """Replicates geo location message."""
        geo = getattr(message.media, "geo", None)
        if geo:
            lat = getattr(geo, "lat", 0.0)
            long = getattr(geo, "long", 0.0)
            location_text = f"📍 Location: https://maps.google.com/?q={lat},{long}"
            sent = await self.bot_client.send_message(
                entity=self.destination_chat_id,
                message=location_text,
                reply_to=reply_to_id,
            )
            if sent and hasattr(sent, "id"):
                self._record_reply_mapping(message.id, sent.id)

    async def _replicate_contact(self, message: Any, reply_to_id: Optional[int]) -> None:
        """Replicates contact card message."""
        contact = message.media
        first_name = getattr(contact, "first_name", "")
        last_name = getattr(contact, "last_name", "") or ""
        phone = getattr(contact, "phone_number", "")
        contact_text = f"👤 Contact: {first_name} {last_name} ({phone})".strip()

        sent = await self.bot_client.send_message(
            entity=self.destination_chat_id,
            message=contact_text,
            reply_to=reply_to_id,
        )
        if sent and hasattr(sent, "id"):
            self._record_reply_mapping(message.id, sent.id)
