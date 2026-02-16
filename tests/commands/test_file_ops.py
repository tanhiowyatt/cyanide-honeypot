import pytest
from cyanide.vfs.commands.file_ops import TouchCommand, MkdirCommand, RmCommand, CpCommand, MvCommand
from cyanide.core.emulator import ShellEmulator

@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")

@pytest.mark.asyncio
async def test_touch(shell, mock_fs):
    cmd = TouchCommand(shell)
    
    # New file
    stdout, stderr, rc = await cmd.execute(["test.txt"])
    assert rc == 0
    assert mock_fs.exists("/root/test.txt")
    
    # Update timestamp (mocked effect, just checking it doesn't crash)
    stdout, stderr, rc = await cmd.execute(["test.txt"])
    assert rc == 0

@pytest.mark.asyncio
async def test_mkdir(shell, mock_fs):
    cmd = MkdirCommand(shell)
    
    # Simple mkdir
    stdout, stderr, rc = await cmd.execute(["dir1"])
    assert rc == 0
    assert mock_fs.is_dir("/root/dir1")
    
    # Recursive mkdir -p
    stdout, stderr, rc = await cmd.execute(["-p", "a/b/c"])
    assert rc == 0
    assert mock_fs.is_dir("/root/a/b/c")
    
    # Fail on existing without -p (if implemented) or simple fail
    mock_fs.mkfile("/root/file")
    stdout, stderr, rc = await cmd.execute(["file"])
    assert rc != 0

@pytest.mark.asyncio
async def test_rm(shell, mock_fs):
    cmd = RmCommand(shell)
    
    mock_fs.mkfile("/root/file.txt")
    mock_fs.mkdir_p("/root/dir")
    
    # Remove file
    stdout, stderr, rc = await cmd.execute(["file.txt"])
    assert rc == 0
    assert not mock_fs.exists("/root/file.txt")
    
    # Remove dir (should fail without -r)
    stdout, stderr, rc = await cmd.execute(["dir"])
    assert rc != 0
    assert mock_fs.exists("/root/dir")
    
    # Remove dir with -r
    stdout, stderr, rc = await cmd.execute(["-r", "dir"])
    assert rc == 0
    assert not mock_fs.exists("/root/dir")
    
    # Force -f (ignore missing)
    stdout, stderr, rc = await cmd.execute(["-f", "missing"])
    assert rc == 0

@pytest.mark.asyncio
async def test_cp(shell, mock_fs):
    cmd = CpCommand(shell)
    
    mock_fs.mkfile("/root/src.txt", content="data")
    
    # Copy file
    stdout, stderr, rc = await cmd.execute(["src.txt", "dst.txt"])
    assert rc == 0
    assert mock_fs.get_content("/root/dst.txt") == "data"
    
    # Recursive copy (if implemented)
    mock_fs.mkdir_p("/root/src_dir")
    mock_fs.mkfile("/root/src_dir/f.txt")
    
    stdout, stderr, rc = await cmd.execute(["-r", "src_dir", "dst_dir"])
    assert rc == 0
    assert mock_fs.exists("/root/dst_dir/f.txt")

@pytest.mark.asyncio
async def test_mv(shell, mock_fs):
    cmd = MvCommand(shell)
    
    mock_fs.mkfile("/root/src.txt", content="data")
    
    # Move file
    stdout, stderr, rc = await cmd.execute(["src.txt", "dst.txt"])
    assert rc == 0
    assert not mock_fs.exists("/root/src.txt")
    assert mock_fs.get_content("/root/dst.txt") == "data"
    
    # Move into dir
    mock_fs.mkdir_p("/root/dir")
    stdout, stderr, rc = await cmd.execute(["dst.txt", "dir/"])
    assert rc == 0
    assert mock_fs.exists("/root/dir/dst.txt")
    
