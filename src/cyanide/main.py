import asyncio
import signal
import sys
import os
import warnings
import logging
from pathlib import Path

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

from cyanide.core import HoneypotServer, load_config
from cyanide.core.aesthetics import print_startup_banner

CONFIG_PATH = Path("config/cyanide.cfg")

def is_docker():
    """Detect if running inside a Docker container."""
    return os.path.exists('/.dockerenv') or os.environ.get('DOCKER_CONTAINER')

async def async_main():
    """Main entry point."""
    # Silence noise ONLY if NOT in Docker
    if not is_docker():
        warnings.filterwarnings("ignore")
        logging.getLogger('asyncssh').setLevel(logging.ERROR)
        # We don't silence everything here to allow debugging if needed, 
        # but we hide the known noisy ones.
    
    config = load_config(CONFIG_PATH)
    print_startup_banner(config)
        
    server = HoneypotServer(config)
    
    # Handle signals gracefully
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: sys.exit(0))
        
    print("[*] Starting Cyanide Honeypot...")
    await server.start()

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

