"""Unit tests for Zero-Disk Replicator."""

import asyncio
from unittest.mock import AsyncMock, MagicMock
from src.replicator import MessageReplicator


def test_text_message_replication():
    async def _run():
        bot_client = MagicMock()
        bot_sent = MagicMock()
        bot_sent.id = 9001
        bot_client.send_message = AsyncMock(return_value=bot_sent)

        user_client = MagicMock()
        replicator = MessageReplicator(bot_client, destination_chat_id=-1002222222222)

        source_msg = MagicMock()
        source_msg.id = 101
        source_msg.media = None
        source_msg.text = "Hello world!"
        source_msg.message = "Hello world!"
        source_msg.entities = []
        source_msg.reply_to_msg_id = None
        source_msg.web_preview = False

        await replicator.replicate(source_msg, user_client)

        bot_client.send_message.assert_called_once_with(
            entity=-1002222222222,
            message="Hello world!",
            formatting_entities=[],
            link_preview=False,
            reply_to=None,
        )
        assert replicator._get_destination_reply_id(101) == 9001

    asyncio.run(_run())


def test_reply_threading_preservation():
    async def _run():
        bot_client = MagicMock()
        first_sent = MagicMock(id=5001)
        second_sent = MagicMock(id=5002)
        bot_client.send_message = AsyncMock(side_effect=[first_sent, second_sent])

        user_client = MagicMock()
        replicator = MessageReplicator(bot_client, destination_chat_id=-1002222222222)

        # Message 1
        msg1 = MagicMock(id=10, media=None, text="Parent", message="Parent", entities=[], reply_to_msg_id=None)
        await replicator.replicate(msg1, user_client)

        # Message 2 replying to Message 1
        msg2 = MagicMock(id=11, media=None, text="Child Reply", message="Child Reply", entities=[], reply_to_msg_id=10)
        await replicator.replicate(msg2, user_client)

        assert bot_client.send_message.call_count == 2
        # Check that msg2 had reply_to=5001 (the destination id of parent)
        second_call = bot_client.send_message.call_args_list[1]
        assert second_call.kwargs["reply_to"] == 5001

    asyncio.run(_run())


def test_media_streaming_and_memory_cleaning():
    async def _run():
        bot_client = MagicMock()
        bot_sent = MagicMock(id=8888)
        bot_client.send_file = AsyncMock(return_value=bot_sent)

        user_client = MagicMock()
        # Mock download_media writing bytes to the in-memory buffer
        async def fake_download(msg, file):
            file.write(b"fake-image-bytes-in-ram")
        user_client.download_media = AsyncMock(side_effect=fake_download)

        replicator = MessageReplicator(bot_client, destination_chat_id=-1002222222222)

        media_msg = MagicMock()
        media_msg.id = 202
        media_msg.media = MagicMock()  # Generic photo/doc
        media_msg.file.size = 1024
        media_msg.file.name = "photo.jpg"
        media_msg.text = "Look at this photo"
        media_msg.message = "Look at this photo"
        media_msg.entities = []
        media_msg.reply_to_msg_id = None
        media_msg.voice = False
        media_msg.video_note = False
        media_msg.document = None

        await replicator.replicate(media_msg, user_client)

        user_client.download_media.assert_called_once()
        bot_client.send_file.assert_called_once()
        call_kwargs = bot_client.send_file.call_args.kwargs
        assert call_kwargs["caption"] == "Look at this photo"
        assert replicator._get_destination_reply_id(202) == 8888

    asyncio.run(_run())


def test_media_exceeding_ram_limit_sends_notice():
    async def _run():
        bot_client = MagicMock()
        bot_client.send_message = AsyncMock(return_value=MagicMock(id=9999))
        user_client = MagicMock()

        # Set max 1 MB
        replicator = MessageReplicator(bot_client, destination_chat_id=-1002222222222, max_media_size_mb=1)

        huge_media = MagicMock()
        huge_media.id = 303
        huge_media.media = MagicMock()
        huge_media.file.size = 50 * 1024 * 1024  # 50 MB
        huge_media.text = "Huge video file"
        huge_media.message = "Huge video file"
        huge_media.reply_to_msg_id = None

        await replicator.replicate(huge_media, user_client)

        # download_media should NOT be called to avoid RAM exhaustion
        user_client.download_media.assert_not_called()
        bot_client.send_message.assert_called_once()
        call_message = bot_client.send_message.call_args.kwargs["message"]
        assert "exceeded the in-memory size threshold" in call_message

    asyncio.run(_run())
