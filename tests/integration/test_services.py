import pytest
import asyncio
import asyncssh
import telnetlib3
from cyanide.core.server import HoneypotServer
from cyanide.core.stats import StatsManager

# Mocks and fixtures would be better, but for integration we might want to spin up the server
# However, spinning up the full server might be heavy. 
# Let's mock the server dependencies or use a light config.

@pytest.fixture
def server_config(tmp_path):
    return {
        "ssh": {"enabled": True, "port": 0, "backend_mode": "emulated"}, # Port 0 for dynamic
        "telnet": {"enabled": True, "port": 0, "backend_mode": "emulated"},
        "metrics": {"enabled": False}, # Disable metrics for now to avoid port conflict
        "log_path": str(tmp_path / "logs"),
        "quarantine_path": str(tmp_path / "quarantine"),
        "users": [{"user": "root", "pass": "toor"}, {"user": "admin", "pass": "admin"}],
        "ml": {"enabled": False} 
    }

@pytest.fixture
async def honeypot_server(server_config):
    server = HoneypotServer(server_config)
    task = asyncio.create_task(server.start())
    
    # Wait for servers to start and bind
    for _ in range(10):
        if server.ssh_server and server.telnet_server:
            break
        await asyncio.sleep(0.5)
        
    yield server
    
    await server.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

@pytest.mark.asyncio
async def test_ssh_connection(honeypot_server):
    """Test that SSH server accepts connections."""
    port = honeypot_server.ssh_server.sockets[0].getsockname()[1]
    print(f"Testing SSH on port {port}")
    try:
        async with asyncssh.connect("127.0.0.1", port=port, known_hosts=None, username="root", password="toor", client_keys=None) as conn:
            assert conn.get_extra_info('peername') is not None
    except Exception as e:
        pytest.fail(f"SSH connection failed: {e}")

@pytest.mark.asyncio
async def test_ssh_auth_failure(honeypot_server):
    """Test invalid SSH credentials."""
    port = honeypot_server.ssh_server.sockets[0].getsockname()[1]
    with pytest.raises(asyncssh.PermissionDenied):
        async with asyncssh.connect("127.0.0.1", port=port, known_hosts=None, username="root", password="wrongpassword", client_keys=None):
            pass

@pytest.mark.asyncio
async def test_telnet_connection(honeypot_server):
    """Test Telnet connection and auth."""
    port = honeypot_server.telnet_server.sockets[0].getsockname()[1]
    print(f"Testing Telnet on port {port}")
    reader, writer = await telnetlib3.open_connection("127.0.0.1", port)
    
    # Expect login prompt
    out = await reader.readuntil(b"login: ")
    assert b"login: " in out
    writer.write("root\n")
    
    out = await reader.readuntil(b"Password: ")
    assert b"Password: " in out
    writer.write("toor\n")
    
    # Expect shell prompt
    out = await reader.readuntil(b"$ ")
    assert b"root@server:~$" in out
    
    writer.close()

