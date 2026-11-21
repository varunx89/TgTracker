"""
Main Tracker Service orchestrator for TgTracker.

Initializes encrypted session decryption, memory-only Telethon clients,
active sandboxing, strict source-chat event listeners, and graceful lifecycle shutdown.
"""

import asyncio
import logging
import signal
from typing import Optional
from telethon import TelegramClient, events
from telethon.sessions import MemorySession, StringSession

from src.config import TrackerConfig
from src.crypto import (
    decode_envelope_b64,
    decrypt_session_string,
    read_secure_file,
)
from src.replicator import MessageReplicator
from src.security_guard import (
    apply_bot_client_sandbox,
    apply_user_client_sandbox,
    canonicalize_chat_identifiers,
    is_event_strictly_authorized,
)

logger = logging.getLogger("TgTracker.Service")


class TrackerService:
    """
    High-security Telegram message tracking service.
    """

    def __init__(self, config: TrackerConfig):
        self.config = config
        self.user_client: Optional[TelegramClient] = None
        self.bot_client: Optional[TelegramClient] = None
        self.replicator: Optional[MessageReplicator] = None
        self._running = False
        self._shutdown_event = asyncio.Event()

    def _decrypt_session(self) -> str:
        """
        Loads and decrypts the Telethon StringSession using AES-256-GCM.
        Returns the decrypted plaintext session string in memory.
        """
        logger.info("Decrypting user session from %s storage...", self.config.session_storage_mode)
        if self.config.session_storage_mode == "file":
            envelope_bytes = read_secure_file(self.config.encrypted_session_file)
        else:
            if not self.config.encrypted_session_string:
                raise ValueError("Missing ENCRYPTED_SESSION_STRING")
            envelope_bytes = decode_envelope_b64(self.config.encrypted_session_string)

        session_string = decrypt_session_string(envelope_bytes, self.config.session_encryption_key)
        # Ensure envelope bytes are discarded
        del envelope_bytes
        return session_string

    async def start(self) -> None:
        """
        Initializes, sandboxes, and boots the user tracking and bot replication clients.
        """
        logger.info("Starting TgTracker Security Service...")
        allowed_source_ids = canonicalize_chat_identifiers(self.config.source_track_chat_id)
        logger.info("Strict Whitelist Canonical Source IDs: %s", allowed_source_ids)

        # 1. Decrypt user session in-memory
        raw_session_str = self._decrypt_session()

        try:
            # 2. Instantiate User Client with StringSession (zero SQLite files on disk)
            self.user_client = TelegramClient(
                StringSession(raw_session_str),
                self.config.telegram_api_id,
                self.config.telegram_api_hash,
                device_model=self.config.device_model,
                system_version=self.config.system_version,
                app_version=self.config.app_version,
                flood_sleep_threshold=self.config.flood_sleep_threshold,
                auto_reconnect=True,
                connection_retries=10,
                retry_delay=5,
            )
        finally:
            # Wipe raw session string variable from local stack immediately
            raw_session_str = "0" * len(raw_session_str)
            del raw_session_str

        # 3. Apply active sandbox on User Client (Strict Read-Only, No Dialogs, Source Only)
        apply_user_client_sandbox(self.user_client, self.config.source_track_chat_id)

        # 4. Instantiate Bot Client with MemorySession (100% RAM resident)
        self.bot_client = TelegramClient(
            MemorySession(),
            self.config.telegram_api_id,
            self.config.telegram_api_hash,
            device_model=f"{self.config.device_model}-Bot",
            system_version=self.config.system_version,
            app_version=self.config.app_version,
            flood_sleep_threshold=self.config.flood_sleep_threshold,
            auto_reconnect=True,
            connection_retries=10,
            retry_delay=5,
        )

        # 5. Apply active sandbox on Bot Client (Destination Chat Only)
        apply_bot_client_sandbox(self.bot_client, self.config.destination_receive_chat_id)

        # 6. Connect User Client
        await self.user_client.connect()
        if not await self.user_client.is_user_authorized():
            raise PermissionError("User session authentication failed. Run login.py to authenticate.")

        me = await self.user_client.get_me()
        user_display = getattr(me, "first_name", "User")
        logger.info("User client connected successfully as: %s (ID: %s)", user_display, me.id)

        # Verify access to the tracked source chat
        source_entity = await self.user_client.get_entity(self.config.source_track_chat_id)
        logger.info("Verified access to source chat: %s", getattr(source_entity, "title", str(self.config.source_track_chat_id)))

        # 7. Start Bot Client
        await self.bot_client.start(bot_token=self.config.telegram_bot_token)
        bot_me = await self.bot_client.get_me()
        logger.info("Bot client connected successfully as: @%s (ID: %s)", bot_me.username, bot_me.id)

        # Verify bot access to destination chat
        dest_entity = await self.bot_client.get_entity(self.config.destination_receive_chat_id)
        logger.info("Verified bot access to destination chat: %s", getattr(dest_entity, "title", str(self.config.destination_receive_chat_id)))

        # 8. Initialize Replicator Engine
        self.replicator = MessageReplicator(
            bot_client=self.bot_client,
            destination_chat_id=self.config.destination_receive_chat_id,
            replicate_media=self.config.replicate_media,
            max_media_size_mb=self.config.max_media_size_mb,
            preserve_replies=self.config.preserve_replies,
        )

        # 9. Synchronize channel state & entity cache for MTProto channel updates
        # Since get_dialogs() is sandboxed for zero-access privacy, Telethon's internal MessageBox
        # and EntityCache must be explicitly initialized with the authorized channel's access_hash
        # and current PTS sequence. Without this, Telegram channel differences and UpdateChannelTooLong
        # events are silently dropped by MTProto client loops.
        from telethon import functions, utils
        try:
            try:
                bare_channel_id = utils.get_peer_id(source_entity, add_mark=False)
            except Exception:
                raw_id = getattr(source_entity, "id", None) or getattr(source_entity, "channel_id", None)
                bare_channel_id = int(raw_id) if raw_id is not None else abs(int(str(self.config.source_track_chat_id).replace("-100", "")))

            # Ensure channel access_hash is in EntityCache
            if hasattr(self.user_client, "_mb_entity_cache"):
                self.user_client._mb_entity_cache.extend([], [source_entity])

            # Query initial message history to resolve active PTS
            input_peer = await self.user_client.get_input_entity(source_entity)
            history = await self.user_client(functions.messages.GetHistoryRequest(
                peer=input_peer,
                offset_id=0,
                offset_date=None,
                add_offset=0,
                limit=1,
                max_id=0,
                min_id=0,
                hash=0,
            ))

            channel_pts = getattr(history, "pts", None)
            if hasattr(self.user_client, "_message_box"):
                if channel_pts:
                    self.user_client._message_box.try_set_channel_state(bare_channel_id, channel_pts)
                    logger.info("Synchronized channel MTProto state (pts: %s) for source chat.", channel_pts)
                else:
                    self.user_client._message_box.try_set_channel_state(bare_channel_id, 1)

            if hasattr(history, "chats") and hasattr(self.user_client, "_mb_entity_cache"):
                self.user_client._mb_entity_cache.extend(getattr(history, "users", []), history.chats)

        except Exception as e:
            logger.warning("Could not synchronize channel MTProto state: %s. Using default baseline.", type(e).__name__)
            try:
                bare_channel_id = utils.get_peer_id(source_entity, add_mark=False)
                if hasattr(self.user_client, "_message_box"):
                    self.user_client._message_box.try_set_channel_state(bare_channel_id, 1)
            except Exception:
                pass

        # Subscribe to MTProto account update stream
        try:
            await self.user_client(functions.updates.GetStateRequest())
            logger.info("Subscribed to Telegram MTProto real-time update stream.")
        except Exception as e:
            logger.warning("Could not send GetStateRequest: %s", type(e).__name__)

        # Catch up any pending channel updates
        try:
            if hasattr(self.user_client, "catch_up"):
                await self.user_client.catch_up()
                logger.info("Triggered MTProto catch_up() for pending updates.")
        except Exception as e:
            logger.warning("Could not complete catch_up: %s", type(e).__name__)

        # 10. Register strictly guarded message listener
        @self.user_client.on(events.NewMessage(chats=source_entity))
        async def on_new_message(event):
            # Double-check gatekeeper filter for complete defense-in-depth
            if not is_event_strictly_authorized(event, allowed_source_ids):
                # Suppress peer IDs in log to protect personal account privacy
                del event
                return

            logger.info("New message received [ID: %s] from tracked source chat -> Replicating...", event.message.id)
            try:
                await self.replicator.replicate(event.message, self.user_client)
            except Exception as e:
                # Sanitize error to avoid leaking message snippets or user info
                logger.error("Error in replication pipeline: %s", type(e).__name__)
            finally:
                del event

        @self.user_client.on(events.Raw())
        async def on_raw_update(event):
            # Safe diagnostic logging of raw MTProto updates (type name only, zero payload)
            logger.debug("Raw MTProto event received: %s", type(event).__name__)

        self._running = True
        logger.info("TgTracker is ACTIVE. Listening strictly on group: %s", self.config.source_track_chat_id)

    async def run_until_disconnected(self) -> None:
        """Runs the service until interrupted or stopped."""
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop)
            except (NotImplementedError, RuntimeError):
                pass

        # Concurrently run Telethon update loop and watch for shutdown signal
        shutdown_waiter = asyncio.create_task(self._shutdown_event.wait())
        client_waiter = asyncio.create_task(self.user_client.run_until_disconnected())

        done, pending = await asyncio.wait(
            [shutdown_waiter, client_waiter],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        await self.cleanup()

    def stop(self) -> None:
        """Signals graceful shutdown."""
        logger.info("Stopping TgTracker Service...")
        self._running = False
        self._shutdown_event.set()

    async def cleanup(self) -> None:
        """Disconnects clients and securely wipes memory."""
        logger.info("Cleaning up connections and memory...")
        if self.user_client and self.user_client.is_connected():
            await self.user_client.disconnect()
        if self.bot_client and self.bot_client.is_connected():
            await self.bot_client.disconnect()
        logger.info("TgTracker terminated securely.")
