import pytest
import asyncio
import threading
import time
import os
import signal
import sys
import configparser
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent))

# Import from src instead of honeypot
sys.path.append(str(Path(__file__).parent.parent / "src"))
from core.server import HoneypotServer

CONFIG_PATH = Path("etc/cyanide.cfg")

@pytest.fixture(scope="session")
def honeypot_server():
    """Start the honeypot server in a separate process for the session."""
    
    # Load config manually to get ports
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_PATH)
    ssh_port = cfg.getint("ssh", "listen_port", fallback=2222)
    telnet_port = cfg.getint("telnet", "listen_port", fallback=2223)
    
    # Check if ports are available first, kill if needed
    os.system(f"lsof -t -i :{ssh_port} | xargs kill -9 2>/dev/null || true")
    os.system(f"lsof -t -i :{telnet_port} | xargs kill -9 2>/dev/null || true")
    
    # Start server as subprocess
    import subprocess
    
    log_dir = Path("var/log/cyanide")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    env = os.environ.copy()
    env['PYTHONPATH'] = str(Path().resolve() / "src")
    # Redirect logs for tests? Use defaults for now.
    
    # Run main.py
    with open(log_dir / "test_server.out", "w") as out:
        process = subprocess.Popen(
            [sys.executable, "main.py"],
            stdout=out,
            stderr=subprocess.STDOUT,
            cwd=str(Path(".").resolve()),
            env=env
        )
    
    start_time = time.time()
    created = False
    while time.time() - start_time < 10:
        import socket
        try:
            with socket.create_connection(("127.0.0.1", ssh_port), timeout=0.1):
                created = True
                break
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
            
    if not created:
         process.kill()
         print("Timeout waiting for server to start.")
         raise RuntimeError("Server failed to start")
            
    yield process
    
    try:
        process.terminate()
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
