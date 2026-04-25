import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cyanide.vfs.engine import FakeFilesystem
from cyanide.vfs.profile_loader import _compute_hash, _flatten_nodes, invalidate
from cyanide.vfs.scp import ScpHandler


@pytest.fixture
def fs(tmp_path):
    # Mock history storage
    history_dir = tmp_path / "var/lib/cyanide/history"
    history_dir.mkdir(parents=True)
    with patch(
        "cyanide.vfs.engine.Path",
        side_effect=lambda *args: (
            Path(*args) if "var/lib/cyanide" not in str(args) else tmp_path / Path(*args)
        ),
    ):
        yield FakeFilesystem(src_ip="1.2.3.4")


def test_vfs_history_loading_saving(tmp_path):
    # Completely isolated test for history
    with patch("cyanide.vfs.engine.Path") as mock_path_cls:
        mock_file = MagicMock()
        mock_file.exists.return_value = True
        mock_file.read_text.return_value = "ls -la\nwhoami\n"
        mock_file.stat.return_value.st_mtime = 123456789

        # Setup mock Path chain: Path(...) / src_ip / .bash_history
        mock_path_cls.return_value.__truediv__.return_value.__truediv__.return_value = mock_file

        fs = FakeFilesystem(src_ip="1.2.3.4")
        # The constructor calls _load_ip_history

        assert fs.exists("/root/.bash_history")
        content = fs.get_content("/root/.bash_history")
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        assert "ls -la" in content

        # Test saving
        fs.mkfile("/root/.bash_history", content="new command\n")
        fs.save_ip_history()
        mock_file.write_text.assert_called_with("new command\n")


def test_vfs_user_home_initialization(fs):
    fs.users = [{"user": "testuser"}]
    fs._initialize_user_homes()
    assert fs.is_dir("/home/testuser")
    assert fs.exists("/home/testuser/.bashrc")
    assert fs.is_dir("/home/testuser/.ssh")
    node = fs.get_node("/home/testuser/.ssh")
    assert node.perm == "drwx------"


@pytest.mark.asyncio
async def test_scp_edge_cases(tmp_path):
    session = MagicMock()
    session.honeypot.get_filesystem.return_value = FakeFilesystem()
    session.src_ip = "1.1.1.1"
    session.session_id = "sess1"

    handler = ScpHandler(session)

    # Test invalid header
    handler._write = MagicMock()
    await handler._handle_copy_command("INVALID HEADER", "/tmp")
    handler._write.assert_called_with(b"\x01SCP Protocol Error: Invalid header\n")

    # Test directory creation failure mock
    handler.fs.mkdir_p = MagicMock(side_effect=Exception("mkdir failed"))
    handler._handle_dir_command("D0755 0 testdir", "/tmp")
    # Should log error but not crash

    # Test scp metadata unknown direction
    is_sink, is_source, path = handler._parse_scp_metadata("scp unknown_cmd")
    assert is_sink is False
    assert is_source is False


def test_profile_loader_edge_cases(tmp_path):
    # Test compute hash with marker
    p1 = tmp_path / "p1"
    p1.mkdir()
    base = p1 / "base.yaml"
    base.write_text("metadata: {}")
    static = p1 / "static.yaml"
    static.write_text("static: {}")
    rootfs = p1 / "rootfs"
    rootfs.mkdir()
    marker = rootfs / ".cyanide_vfs_marker"
    marker.write_text("test")

    h1 = _compute_hash(base, static, rootfs)
    os.utime(marker, (time.time() + 100, time.time() + 100))
    h2 = _compute_hash(base, static, rootfs)
    assert h1 != h2

    # Test flatten nodes unexpected type
    with patch("cyanide.vfs.profile_loader.logger") as mock_logger:
        _flatten_nodes({"key": 123})
        mock_logger.warning.assert_called()

    # Test invalidate single profile
    from cyanide.vfs.profile_loader import _MEMORY_CACHE

    _MEMORY_CACHE["test_profile"] = {"hash": "abc"}
    invalidate("test_profile")
    assert "test_profile" not in _MEMORY_CACHE


@pytest.mark.asyncio
async def test_scp_source_mode(tmp_path):
    from unittest.mock import AsyncMock

    session = MagicMock()
    fs = FakeFilesystem()
    fs.mkfile("/test.txt", content="hello scp")
    session.fs = fs
    session.honeypot.logger = MagicMock()

    handler = ScpHandler(session)
    handler._read = AsyncMock(
        side_effect=[b"\0", b"\0", b"\0"]
    )  # Initial ACK, Header ACK, Content ACK
    handler._write = MagicMock()

    rc = await handler._handle_source_mode("/test.txt")
    assert rc == 0
    # Verify header sent
    header_call = handler._write.call_args_list[0]
    assert b"C0644 9 test.txt" in header_call[0][0]


def test_profile_loader_db_error(tmp_path):
    from cyanide.vfs.profile_loader import _compile_to_sqlite

    manifest = {"/test": {"type": "file", "content": "test"}}
    # Use a directory as db_path to trigger error
    db_dir = tmp_path / "bad_db"
    db_dir.mkdir()

    with patch("cyanide.vfs.profile_loader.logger") as mock_logger:
        _compile_to_sqlite(manifest, db_dir, "hash123")
        mock_logger.warning.assert_called()
