import asyncio
import logging
import os
import signal
import sys
import warnings
from pathlib import Path

# Add src to path if not already there
parent_dir = str(Path(__file__).resolve().parent.parent)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from cyanide.core import CyanideServer, load_config  # noqa: E402
from cyanide.core.aesthetics import print_startup_banner  # noqa: E402

CONFIG_PATH = Path("configs/app.yaml")


# Function 106: Checks condition: is docker.
def is_docker():
    """Detect if running inside a Docker container."""
    return os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER")


# Function 107: Main entry point for the application execution.
async def async_main():
    """Main entry point."""
    # Silence noise ONLY if NOT in Docker
    if not is_docker():
        warnings.filterwarnings("ignore")
        logging.getLogger("asyncssh").setLevel(logging.ERROR)
        # We don't silence everything here to allow debugging if needed,
        # but we hide the known noisy ones.

    config = load_config(CONFIG_PATH)

    server = CyanideServer(config)
    print_startup_banner(config, resolved_profile=server.resolved_profile_name)

    # Handle signals gracefully
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: sys.exit(0))

    print("[*] Starting Cyanide Honeypot...")
    await server.start()


# Function 108: Main entry point for the application execution.
def main():
    """Synchronous entry point for console_scripts."""
    try:
        asyncio.run(async_main())
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Honeypot stopped.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    main()
