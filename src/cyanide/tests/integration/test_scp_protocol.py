import asyncio
import os
import pytest
import asyncssh
import tempfile
from pathlib import Path

# Test configurations
HOST = "127.0.0.1"
PORT = int(os.getenv("CYANIDE_SSH_PORT", 2222))
USERS = [
    ("root", "admin"),
    ("admin", "admin"),
    ("user", "123456"),
]
TARGET_DIRS = [
    "/root",
    "/tmp",
    "/home/admin",
    "/home/user",
]

@pytest.mark.asyncio
@pytest.mark.parametrize("username, password", USERS)
@pytest.mark.parametrize("target_dir", TARGET_DIRS)
async def test_scp_upload_download(username, password, target_dir):
    """
    Test SCP upload and download for multiple users and directories.
    Verify content integrity and VFS visibility.
    """
    filename = f"test_scp_{username}_{target_dir.replace('/', '_')}.txt"
    content = f"Content for {username} in {target_dir} - unique id {os.urandom(4).hex()}"
    
    with tempfile.TemporaryDirectory() as tmpdir:
        local_upload_path = Path(tmpdir) / "upload.txt"
        local_download_path = Path(tmpdir) / "download.txt"
        
        # 1. Create unique file
        local_upload_path.write_text(content)
        
        try:
            async with asyncssh.connect(
                HOST, port=PORT, username=username, password=password, known_hosts=None
            ) as conn:
                # 2. Upload via SCP
                remote_path = f"{target_dir}/{filename}"
                await asyncssh.scp(local_upload_path, (conn, remote_path))
                
                # 3. Verify visibility via SSH command (optional but good for VFS check)
                result = await conn.run(f"ls {remote_path}", check=True)
                assert filename in result.stdout
                
                # 4. Download via SCP
                await asyncssh.scp((conn, remote_path), local_download_path)
                
                # 5. Verify integrity
                downloaded_content = local_download_path.read_text()
                assert downloaded_content == content
                
        except Exception as e:
            pytest.fail(f"SCP Protocol test failed for {username} at {target_dir}: {e}")

@pytest.mark.asyncio
@pytest.mark.parametrize("username, password", USERS)
async def test_scp_recursive_upload(username, password):
    """
    Test recursive SCP upload of a directory.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        local_dir = Path(tmpdir) / "recursive_test"
        local_dir.mkdir()
        file1 = local_dir / "file1.txt"
        file2 = local_dir / "file2.txt"
        file1.write_text("file1 content")
        file2.write_text("file2 content")
        
        try:
            async with asyncssh.connect(
                HOST, port=PORT, username=username, password=password, known_hosts=None
            ) as conn:
                remote_dir = "/tmp/recursive_test"
                await asyncssh.scp(local_dir, (conn, remote_dir), recurse=True)
                
                # Verify files exist in VFS
                result = await conn.run(f"ls -R {remote_dir}", check=True)
                assert "file1.txt" in result.stdout
                assert "file2.txt" in result.stdout
                
        except Exception as e:
             pytest.fail(f"Recursive SCP upload failed for {username}: {e}")
