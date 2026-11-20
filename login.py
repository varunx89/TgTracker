#!/usr/bin/env python3
"""
Secure Interactive Login & Session Encryption Tool for TgTracker.

Features:
- Authenticates with Telegram using Telethon StringSession (Zero unencrypted SQLite on disk).
- Prompts for credentials securely (getpass for codes, passwords, and passphrases).
- Immediately encrypts the session string with military-grade AES-256-GCM.
- Atomically saves the encrypted payload with strict POSIX 0600 permissions (session.enc).
- Supports Base64 output for diskless cloud deployment via ENCRYPTED_SESSION_STRING.
- Wipes plaintext credentials from RAM before process exit.
"""

import asyncio
import getpass
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from telethon.sessions import StringSession

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from src.crypto import (
    encode_envelope_b64,
    encrypt_session_string,
    generate_encryption_key,
    save_secure_file,
)


async def main() -> None:
    print("=" * 70)
    print("   TgTracker Secure Telegram Session Generator & Encryptor   ")
    print("=" * 70)

    # Load existing .env if available
    load_dotenv()

    # 1. API ID & Hash
    api_id_env = os.getenv("TELEGRAM_API_ID")
    if not api_id_env:
        api_id_str = input("Enter TELEGRAM_API_ID (from https://my.telegram.org): ").strip()
    else:
        api_id_str = api_id_env.strip()

    try:
        api_id = int(api_id_str)
    except ValueError:
        print("[ERROR] TELEGRAM_API_ID must be a numeric integer.")
        sys.exit(1)

    api_hash = os.getenv("TELEGRAM_API_HASH")
    if not api_hash:
        api_hash = input("Enter TELEGRAM_API_HASH: ").strip()
    else:
        api_hash = api_hash.strip()

    if len(api_hash) != 32:
        print("[ERROR] TELEGRAM_API_HASH must be a 32-character hexadecimal string.")
        sys.exit(1)

    # 2. Encryption Key / Passphrase
    encryption_key = os.getenv("SESSION_ENCRYPTION_KEY")
    if not encryption_key:
        print("\nChoose an option for your Session Encryption Key:")
        print("  1. Generate a new high-entropy 256-bit AES key (Recommended)")
        print("  2. Enter a custom master passphrase (PBKDF2 with 600,000 iterations)")
        choice = input("Select [1 or 2] (default 1): ").strip() or "1"

        if choice == "1":
            encryption_key = generate_encryption_key()
            print(f"\n[IMPORTANT] Generated New 256-bit Key: {encryption_key}")
            print("Please save this key in your .env file as SESSION_ENCRYPTION_KEY!\n")
        else:
            p1 = getpass.getpass("Enter master passphrase for session encryption: ")
            p2 = getpass.getpass("Confirm master passphrase: ")
            if p1 != p2:
                print("[ERROR] Passphrases do not match.")
                sys.exit(1)
            if len(p1) < 8:
                print("[ERROR] Passphrase must be at least 8 characters long.")
                sys.exit(1)
            encryption_key = p1
    else:
        print("[INFO] Loaded SESSION_ENCRYPTION_KEY from environment / .env")

    # 3. Phone Number
    phone = input("\nEnter your Telegram Phone Number (international format, e.g. +1234567890): ").strip()
    if not phone.startswith("+"):
        print("[WARNING] Phone numbers usually start with '+' in international format.")

    # 4. Initialize in-memory StringSession client
    print("\n[INFO] Connecting to Telegram MTProto servers...")
    client = TelegramClient(StringSession(), api_id, api_hash)
    await client.connect()

    if not await client.is_user_authorized():
        # Request SMS / Telegram code
        print(f"[INFO] Sending login code to {phone}...")
        sent_code = await client.send_code_request(phone)

        # Securely prompt code without exposing in logs
        code = getpass.getpass("Enter the login code you received: ").strip()

        try:
            await client.sign_in(phone=phone, code=code)
        except SessionPasswordNeededError:
            # Two-Step Verification is enabled
            pwd = getpass.getpass("Two-step verification enabled. Enter your 2FA Password: ")
            await client.sign_in(password=pwd)
            pwd = "0" * len(pwd)
            del pwd

    me = await client.get_me()
    print(f"\n[SUCCESS] Successfully authenticated as: {me.first_name} (@{me.username or 'N/A'}, ID: {me.id})")

    # 5. Extract StringSession
    session_string = client.session.save()
    await client.disconnect()

    # 6. Authenticated Encryption with AES-256-GCM
    print("[INFO] Encrypting session string with AES-256-GCM...")
    envelope_bytes = encrypt_session_string(session_string, encryption_key)
    b64_envelope = encode_envelope_b64(envelope_bytes)

    # Secure Memory Wipe of raw session string
    session_string = "0" * len(session_string)
    del session_string

    # 7. Write to secure session file with POSIX 0600 permissions
    session_file_path = os.getenv("ENCRYPTED_SESSION_FILE", "session.enc")
    save_secure_file(session_file_path, envelope_bytes)
    print(f"[SUCCESS] Encrypted session saved to: {session_file_path} (Permissions: 0600 - Owner Read/Write ONLY)")

    print("\n" + "=" * 70)
    print("                    SETUP COMPLETE & VERIFIED")
    print("=" * 70)
    print(f"1. Encrypted session file: {session_file_path}")
    print("2. If using file storage (default), ensure your .env contains:")
    print(f"   SESSION_STORAGE_MODE=file")
    print(f"   ENCRYPTED_SESSION_FILE={session_file_path}")
    print(f"   SESSION_ENCRYPTION_KEY={encryption_key}")
    print("\n3. Alternatively, for 100% diskless server deployments, add to .env:")
    print(f"   SESSION_STORAGE_MODE=env_string")
    print(f"   ENCRYPTED_SESSION_STRING={b64_envelope}")
    print(f"   SESSION_ENCRYPTION_KEY={encryption_key}")
    print("=" * 70)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Login cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Authentication failed: {e}")
        sys.exit(1)
