# TgTracker: High-Security Telegram Message Tracking & Replication Service

A Python service built with **Telethon** designed with zero-trust security and absolute privacy isolation. It monitors a **single specific Telegram group** and clones every incoming message (text with rich formatting, media, documents, audio, stickers, replies) in real time to a **receiving destination group** using a dedicated Telegram bot.

---

## Key Capabilities & Security Highlights

* **Authenticated Session Encryption (AES-256-GCM)**: Login sessions are protected using industry-standard AES-256-GCM with a 12-byte CSPRNG nonce, Associated Authenticated Data (AAD), and tamper-evident tags. Never stores unencrypted SQLite session files on disk.
* **Brute-Force Hardening (PBKDF2-HMAC-SHA256)**: When using a master passphrase, keys are derived using 600,000 PBKDF2 iterations (OWASP standard) with a 32-byte cryptographic salt.
* **Active Chat Isolation & Sandboxing**: Multi-layer defense ensures the tracking account cannot access, enumerate, read, or receive messages from any chat, channel, or personal direct message (DM) other than the single authorized source group.
* **Separation of Concerns**:
  * **User Client**: Strictly **READ-ONLY** and restricted to the tracked source chat. All write/send APIs are permanently blocked.
  * **Bot Client**: Strictly **WRITE-ONLY** and restricted to sending messages to the destination chat.
* **Absolute Zero-Storage Policy**: Messages and media are **NEVER saved to disk**, cached in databases, or persisted. Media is streamed directly through RAM via `io.BytesIO` and wiped immediately after transmission.
* **Zero-Leak Logging**: Log output contains only operational telemetry and sanitized IDs. Message contents, captions, phone numbers, and credentials are never written to logs.
* **POSIX 0600 Permissions**: Files containing encrypted credentials enforce strict owner read/write permissions (`-rw-------`).
* **RAM Safety Guard**: Configurable memory threshold (`MAX_MEDIA_SIZE_MB`) prevents memory exhaustion on lightweight or embedded servers.

---

## Architecture Diagram

```
                 +-----------------------------------------+
                 |          Telegram MTProto               |
                 +-------------------+---------------------+
                                     |
               Inbound Updates (All) |
                                     v
                 +-----------------------------------------+
                 |       Strict Security Gateway           |
                 |  (Canonical ID Filter & DM Drop)        |
                 +-------------------+---------------------+
                                     |
                 Only SOURCE_CHAT_ID |  (All other chats/DMs dropped)
                                     v
+------------------------------------+------------------------------------+
|                               TgTracker                                 |
|                                                                         |
|  +---------------------------+        +------------------------------+  |
|  |     User Client           |        |      Replicator Engine       |  |
|  | - Telethon StringSession  |        | - RAM-Only Streaming         |  |
|  | - In-Memory AES Decrypted | -----> | - Zero Disk Footprint        |  |
|  | - Sandboxed: READ-ONLY    |        | - Preserves Formats & Replies|  |
|  | - Prohibits Dialog Lists  |        | - Immediate Buffer Purge     |  |
|  +---------------------------+        +--------------+---------------+  |
|                                                      |                  |
+------------------------------------------------------|------------------+
                                                       |
                                                       v
                                        +------------------------------+
                                        |         Bot Client           |
                                        | - Sandboxed: DEST_CHAT only  |
                                        | - MemorySession (RAM Only)   |
                                        +--------------+---------------+
                                                       |
                                                       v
                                        +------------------------------+
                                        |   Destination Group (Replica)|
                                        +------------------------------+
```

---

## Directory Structure

```
TgTracker/
├── .env.example              # Fully documented configuration template
├── .gitignore                # Protects secrets, sessions, keys, and environments
├── requirements.txt          # Python dependencies
├── README.md                 # Complete documentation & security rationale
├── login.py                  # Interactive Telegram login and AES-256-GCM encryptor
├── main.py                   # Service entrypoint
├── src/
│   ├── __init__.py
│   ├── config.py             # Strict Pydantic config validation & secret redaction
│   ├── crypto.py             # AES-256-GCM AEAD, PBKDF2 derivation & 0600 file handler
│   ├── security_guard.py     # Active client sandboxing & chat restriction enforcement
│   ├── replicator.py         # Zero-disk message replication engine
│   └── tracker_service.py    # Main lifecycle orchestrator
└── tests/
    ├── test_config.py        # Config validation unit tests
    ├── test_crypto.py        # Cryptographic integrity and tamper detection tests
    ├── test_security_guard.py# Sandbox and chat isolation tests
    ├── test_replicator.py    # RAM streaming & reply mapping tests
    └── test_tracker_service.py # Service lifecycle tests
```

---

## Quick Start & Setup

### 1. Prerequisites & Virtual Environment

Ensure you have Python 3.10+ installed.

```bash
# Clone or navigate to the project directory
cd /path/to/TgTracker

# Create and activate a dedicated virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` and provide your credentials:

```dotenv
# Telegram API credentials from https://my.telegram.org
TELEGRAM_API_ID=12345678
TELEGRAM_API_HASH=0123456789abcdef0123456789abcdef

# Telegram Bot token from @BotFather
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456

# Single source group to track (e.g. -1001234567890)
SOURCE_TRACK_CHAT_ID=-1001234567890

# Destination group where the bot sends replicated messages
DESTINATION_RECEIVE_CHAT_ID=-1009876543210

# Master encryption key (256-bit base64) or strong passphrase
SESSION_ENCRYPTION_KEY=YourSuperSecureAES256GCMKeyOrMasterPassphraseHere!

# Storage mode: 'file' (session.enc) or 'env_string' (100% diskless)
SESSION_STORAGE_MODE=file
ENCRYPTED_SESSION_FILE=session.enc
```

> **Important**: Add your bot as an **Administrator** in the destination group with permission to send messages. The bot does **not** need to be in the source group.

---

### 3. Authenticate and Encrypt the Session

Run `login.py` to authenticate your tracking Telegram account:

```bash
python login.py
```

* It will ask for your phone number, login code, and 2FA password (entered securely using `getpass` without echoing on the terminal).
* It extracts the `StringSession` directly into memory.
* It immediately encrypts the session with **AES-256-GCM** using your `SESSION_ENCRYPTION_KEY`.
* It saves `session.enc` with strict POSIX permissions (`0600` - readable only by you).
* It clears the plaintext session string from memory.

---

### 4. Run the Tracking Service

To run the tracking service:

```bash
python main.py
```

To run in **verification mode** (validates connectivity, decrypts session, verifies chat access, and exits):

```bash
python main.py --verify-only
```

---

## Running Unit Tests

The test suite covers cryptographic integrity, tamper detection, active sandboxing, configuration validation, memory streaming, and service lifecycle.

```bash
python -m pytest tests/
```

Expected output:
```text
============================== 29 passed in 2.21s ==============================
```

---

## Security Practices & Rationale

| Practice | Mechanism | Why It Was Implemented |
|:---|:---|:---|
| **Zero Plaintext Sessions** | AES-256-GCM AEAD encryption | Telegram session authorization keys give complete access to the user account. If leaked, an attacker could hijack the account. Encryption ensures the key is never exposed. |
| **Passphrase Brute-Force Resistance** | PBKDF2-HMAC-SHA256 (600,000 rounds) | Protects against GPU dictionary attacks if a human-chosen passphrase is used as the master key. |
| **Tamper Protection** | AEAD 128-bit Authentication Tag | Any unauthorized bit-flipping, truncation, or modification of the encrypted session immediately aborts decryption. |
| **Zero Disk Storage** | MemorySession & `io.BytesIO` | Guarantees complete compliance with the "never stored anywhere" privacy rule. Media and text never touch disk. |
| **Multi-layer Chat Sandbox** | Client monkey-patching + Event filter | Standard Telethon could be vulnerable to unintended dialog queries or private DM handling. Active interception makes accessing other chats impossible at runtime. |
| **Separation of Duties** | Read-only User + Write-only Bot | Minimizes attack surface. The user account cannot send messages, and the bot cannot read the source group. |
| **Least Privilege File Permissions** | POSIX `0600` atomic creation | Ensures no other user or process on a multi-user Linux system can read the encrypted session file. |
| **Safe Secret Redaction** | Custom Pydantic `__repr__` | Prevents bot tokens, API hashes, or encryption keys from leaking in console logs or error stack traces. |
