"""
Configuration management and validation for TgTracker.
Loads environment variables securely and validates constraints using Pydantic.
Prevents accidental credential leakage in logs via automated secret redaction.
"""

import os
from pathlib import Path
from typing import Literal, Optional, Union
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator, model_validator


class TrackerConfig(BaseModel):
    """
    Validated runtime configuration with strict type enforcement and security policies.
    """
    telegram_api_id: int = Field(..., description="Telegram App API ID from my.telegram.org")
    telegram_api_hash: str = Field(..., min_length=16, description="Telegram App API Hash")
    telegram_bot_token: str = Field(..., min_length=20, description="Telegram Bot Token from @BotFather")

    source_track_chat_id: int = Field(..., description="Target group/channel ID to track strictly")
    destination_receive_chat_id: int = Field(..., description="Receiving group/channel ID for replicated messages")

    session_storage_mode: Literal["file", "env_string"] = Field(
        default="file",
        description="Encrypted session storage mode: 'file' (session.enc) or 'env_string' (ENCRYPTED_SESSION_STRING)"
    )
    session_encryption_key: str = Field(
        ...,
        min_length=8,
        description="AES-256-GCM encryption key (Base64) or strong master passphrase"
    )
    encrypted_session_file: str = Field(
        default="session.enc",
        description="Path to POSIX 0600 encrypted session file"
    )
    encrypted_session_string: Optional[str] = Field(
        default=None,
        description="Base64 encoded encrypted session envelope (if session_storage_mode is 'env_string')"
    )

    replicate_media: bool = Field(default=True, description="Enable RAM-only media cloning (photos, docs, audio, video)")
    max_media_size_mb: int = Field(default=50, ge=1, le=500, description="Max media size (MB) allowed in RAM stream")
    preserve_replies: bool = Field(default=True, description="Preserve reply threading structure in destination group")
    replicate_service_messages: bool = Field(default=False, description="Replicate pin and join service notifications")
    log_level: str = Field(default="INFO", description="Logging level: DEBUG, INFO, WARNING, ERROR")

    device_model: str = Field(default="TgTracker-Secure", description="Device model string reported to Telegram MTProto")
    system_version: str = Field(default="Linux", description="System version reported to Telegram MTProto")
    app_version: str = Field(default="1.0.0", description="App version reported to Telegram MTProto")
    flood_sleep_threshold: int = Field(default=120, ge=0, le=600, description="Max seconds to sleep automatically on flood limits")

    @field_validator("telegram_api_hash")
    @classmethod
    def validate_api_hash(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) != 32:
            raise ValueError("telegram_api_hash must be a 32-character hexadecimal string")
        return clean

    @field_validator("telegram_bot_token")
    @classmethod
    def validate_bot_token(cls, v: str) -> str:
        clean = v.strip()
        if ":" not in clean:
            raise ValueError("Invalid bot token format. Expected '<id>:<token>' from @BotFather")
        return clean

    @model_validator(mode="after")
    def validate_different_chats(self) -> "TrackerConfig":
        if self.source_track_chat_id == self.destination_receive_chat_id:
            raise ValueError(
                "SOURCE_TRACK_CHAT_ID and DESTINATION_RECEIVE_CHAT_ID cannot be identical. "
                "Tracking and receiving chats must be separate to avoid infinite message loops."
            )
        return self

    @model_validator(mode="after")
    def validate_session_source(self) -> "TrackerConfig":
        if self.session_storage_mode == "env_string":
            if not self.encrypted_session_string:
                raise ValueError(
                    "SESSION_STORAGE_MODE is 'env_string', but ENCRYPTED_SESSION_STRING is not set or empty."
                )
        return self

    def __repr__(self) -> str:
        """Safe representation suppressing credentials from tracebacks and logs."""
        return (
            f"<TrackerConfig source={self.source_track_chat_id} "
            f"destination={self.destination_receive_chat_id} "
            f"media={self.replicate_media} max_mb={self.max_media_size_mb} "
            f"storage_mode={self.session_storage_mode} api_hash=*** bot_token=*** secret_key=***>"
        )

    def __str__(self) -> str:
        return self.__repr__()


def load_config(env_path: Optional[Union[str, Path]] = None) -> TrackerConfig:
    """
    Loads configuration from environment and optional .env file.
    Validates all constraints and fails fast with actionable errors.
    """
    if env_path:
        load_dotenv(dotenv_path=env_path, override=True)
    else:
        # Load default .env if present
        load_dotenv(override=False)

    api_id_raw = os.getenv("TELEGRAM_API_ID")
    if not api_id_raw:
        raise ValueError("TELEGRAM_API_ID is required in environment or .env file.")

    try:
        api_id = int(api_id_raw)
    except ValueError:
        raise ValueError(f"TELEGRAM_API_ID must be a numeric integer, got: {api_id_raw}")

    source_id_raw = os.getenv("SOURCE_TRACK_CHAT_ID")
    if not source_id_raw:
        raise ValueError("SOURCE_TRACK_CHAT_ID is required in environment or .env file.")
    try:
        source_id = int(source_id_raw)
    except ValueError:
        raise ValueError(f"SOURCE_TRACK_CHAT_ID must be a numeric ID (e.g. -100...), got: {source_id_raw}")

    dest_id_raw = os.getenv("DESTINATION_RECEIVE_CHAT_ID")
    if not dest_id_raw:
        raise ValueError("DESTINATION_RECEIVE_CHAT_ID is required in environment or .env file.")
    try:
        dest_id = int(dest_id_raw)
    except ValueError:
        raise ValueError(f"DESTINATION_RECEIVE_CHAT_ID must be a numeric ID (e.g. -100...), got: {dest_id_raw}")

    replicate_media_val = os.getenv("REPLICATE_MEDIA", "true").lower() in ("true", "1", "yes")
    preserve_replies_val = os.getenv("PRESERVE_REPLIES", "true").lower() in ("true", "1", "yes")
    replicate_service_val = os.getenv("REPLICATE_SERVICE_MESSAGES", "false").lower() in ("true", "1", "yes")

    return TrackerConfig(
        telegram_api_id=api_id,
        telegram_api_hash=os.getenv("TELEGRAM_API_HASH", ""),
        telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
        source_track_chat_id=source_id,
        destination_receive_chat_id=dest_id,
        session_storage_mode=os.getenv("SESSION_STORAGE_MODE", "file"),  # type: ignore
        session_encryption_key=os.getenv("SESSION_ENCRYPTION_KEY", ""),
        encrypted_session_file=os.getenv("ENCRYPTED_SESSION_FILE", "session.enc"),
        encrypted_session_string=os.getenv("ENCRYPTED_SESSION_STRING"),
        replicate_media=replicate_media_val,
        max_media_size_mb=int(os.getenv("MAX_MEDIA_SIZE_MB", "50")),
        preserve_replies=preserve_replies_val,
        replicate_service_messages=replicate_service_val,
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        device_model=os.getenv("DEVICE_MODEL", "TgTracker-Secure"),
        system_version=os.getenv("SYSTEM_VERSION", "Linux"),
        app_version=os.getenv("APP_VERSION", "1.0.0"),
        flood_sleep_threshold=int(os.getenv("FLOOD_SLEEP_THRESHOLD", "120")),
    )
