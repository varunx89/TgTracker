#!/usr/bin/env python3
"""
TgTracker Main Entrypoint.

Starts the highly secure, sandboxed Telegram tracking service:
- Loads and strictly validates configuration.
- Sets up safe logging (zero message text leakage).
- Decrypts the session in memory.
- Enforces strict chat isolation and single-destination bot replication.
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from src.config import load_config
from src.tracker_service import TrackerService


def setup_secure_logging(log_level_str: str) -> None:
    """
    Configures logging format while guaranteeing zero message payload leakage.
    """
    level = getattr(logging, log_level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Lower Telethon internal debug noise to prevent verbose payload dumps
    logging.getLogger("telethon").setLevel(logging.WARNING)


async def run_tracker(env_file: str | None, verify_only: bool) -> None:
    try:
        config = load_config(env_path=env_file)
    except Exception as e:
        print(f"[FATAL CONFIG ERROR]: {e}", file=sys.stderr)
        sys.exit(1)

    setup_secure_logging(config.log_level)
    logger = logging.getLogger("TgTracker.Main")
    logger.info("Initializing TgTracker with validated configuration...")

    service = TrackerService(config)

    try:
        await service.start()
        if verify_only:
            logger.info("[VERIFY MODE] Connection, sandboxing, and chat access verified successfully. Exiting.")
            await service.cleanup()
            return

        logger.info("Service initialized and running. Press Ctrl+C to terminate.")
        await service.run_until_disconnected()

    except KeyboardInterrupt:
        logger.info("Termination signal received.")
    except Exception as e:
        logger.error("Service encountered fatal error: %s", e)
        sys.exit(1)
    finally:
        await service.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TgTracker: Secure Single-Group Telegram Tracking & Replication Service"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default=None,
        help="Path to custom .env file (default: .env)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify credentials, decrypted session, and chat isolation without entering continuous loop",
    )
    args = parser.parse_args()

    asyncio.run(run_tracker(env_file=args.config, verify_only=args.verify_only))


if __name__ == "__main__":
    main()
