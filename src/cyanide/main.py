import asyncio
import logging
import os
import signal
import sys
import warnings

from pydantic import ValidationError  # noqa: E402

from cyanide.core.aesthetics import print_startup_banner  # noqa: E402
from cyanide.core.config import load_config  # noqa: E402
from cyanide.core.paths import get_default_config_path  # noqa: E402
from cyanide.core.server import CyanideServer  # noqa: E402

CONFIG_PATH = get_default_config_path()


# Function 106: Checks condition: is docker.
def is_docker():
    """Detect if running inside a Docker container."""
    return os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER")


# Function 107: Main entry point for the application execution.
async def async_main():
    """Main entry point."""
    if not is_docker():
        warnings.filterwarnings("ignore")
        logging.getLogger("asyncssh").setLevel(logging.ERROR)

    try:
        config = load_config(CONFIG_PATH)
    except ValidationError as e:
        logging.error(f"Configuration Error:\n{e}")
        sys.exit(1)

    server = CyanideServer(config)
    print_startup_banner(config, resolved_profile=server.resolved_profile_name)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: sys.exit(0))

    logging.info("[*] Starting Cyanide Honeypot...")
    await server.start()


# Function 108: Main entry point for the application execution.
def main():
    """Synchronous entry point for console_scripts."""
    try:
        asyncio.run(async_main())
    except (KeyboardInterrupt, SystemExit):
        logging.info("\n[*] Honeypot stopped.")
        raise
    except Exception as e:
        logging.error(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    main()
