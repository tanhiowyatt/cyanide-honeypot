import asyncio
import os
import tempfile
from pathlib import Path

import asyncssh
import pytest

from cyanide.core.server import CyanideServer

# Test configurations
HOST = "127.0.0.1"
USERS = [
    ("root", "admin"),
]
TARGET_DIRS = [
    "/tmp",
    "/root",
]


@pytest.fixture(scope="function")
async def scp_server(tmp_path):
    """Start a temporary honeypot server for SCP tests."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    config = {
        "ssh": {
            "enabled": True,
            "port": 0,
            "backend_mode": "emulated",
            "auth_delay": 0,
        },
        "telnet": {"enabled": False},
        "smtp": {"enabled": False},
        "metrics": {"enabled": False},
        "users": [
            {"user": "root", "pass": "admin"},
        ],
        "logging": {"directory": str(log_dir)},
        "os_profile": "ubuntu",
    }

    server = CyanideServer(config)
    server_task = asyncio.create_task(server.start())

    # Wait for the server to bind to a port
    port = None
    for _ in range(30):
        if server.ssh_server and server.ssh_server.sockets:
            port = server.ssh_server.sockets[0].getsockname()[1]
            break
        await asyncio.sleep(0.1)

    if port is None:
        server_task.cancel()
        pytest.fail("Failed to start SSH server for SCP integration test")

    yield port

    await server.stop()
    server_task.cancel()


@pytest.mark.asyncio
@pytest.mark.parametrize("username, password", USERS)
@pytest.mark.parametrize("target_dir", TARGET_DIRS)
async def test_scp_upload_download(scp_server, username, password, target_dir):
    """
    Test SCP upload and download for multiple users and directories.
    Verify content integrity and VFS visibility.
    """
    filename = f"test_scp_updown_{username}_{target_dir.replace('/', '_')}.txt"
    content = f"Content for {username} in {target_dir} - unique id {os.urandom(4).hex()}"

    with tempfile.TemporaryDirectory() as tmpdir:
        local_upload_path = Path(tmpdir) / "upload.txt"
        local_download_path = Path(tmpdir) / "download.txt"
        local_upload_path.write_text(content)

        try:
            async with asyncssh.connect(
                HOST,
                port=scp_server,
                username=username,
                password=password,
                known_hosts=None,
                login_timeout=30,
            ) as conn:
                # 2. Upload via SCP
                remote_path = f"{target_dir}/{filename}"
                await asyncssh.scp(local_upload_path, (conn, remote_path))

                # 3. Download via SCP
                await asyncssh.scp((conn, remote_path), local_download_path)

                # 4. Verify integrity
                downloaded_content = local_download_path.read_text()
                assert downloaded_content == content

        except Exception as e:
            pytest.fail(f"SCP Protocol test failed for {username} at {target_dir}: {e}")


@pytest.mark.asyncio
@pytest.mark.parametrize("username, password", USERS)
async def test_scp_recursive_upload(scp_server, username, password):
    """Test recursive SCP upload of a directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        up_dir = base / "recursive_up"
        up_dir.mkdir()
        (up_dir / "file1.txt").write_text("content1")
        (up_dir / "subdir").mkdir()
        (up_dir / "subdir" / "file2.txt").write_text("content2")

        try:
            async with asyncssh.connect(
                HOST,
                port=scp_server,
                username=username,
                password=password,
                known_hosts=None,
                login_timeout=30,
            ) as conn:
                await asyncssh.scp(up_dir, (conn, "/tmp/"), recurse=True)

                # Verify recursion
                res = await conn.run("ls -R /tmp/recursive_up", check=True)
                stdout = str(res.stdout or "")
                assert "file1.txt" in stdout
                assert "subdir" in stdout
                assert "file2.txt" in stdout
        except Exception as e:
            pytest.fail(f"Recursive SCP upload failed for {username}: {e}")
