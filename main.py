import asyncio
import signal
import sys

import os
from pathlib import Path

# Fix path to include src if running from root
sys.path.append(os.path.join(os.getcwd(), 'src'))

from core.server import HoneypotServer

CONFIG_PATH = Path("etc/cyanide.cfg")

from core.config import load_config

async def main():
    """Main entry point."""
    config = load_config(CONFIG_PATH)
        
    server = HoneypotServer(config)
    
    # Handle signals gracefully
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: sys.exit(0))
        
    print("[*] Starting Cyanide Honeypot...")
    await server.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] Honeypot stopped.")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        # sys.exit(1) # Commented out to avoid unclean exit messages during dev

