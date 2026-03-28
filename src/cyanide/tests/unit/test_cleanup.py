import os
import time

from cyanide.core.cleanup import CleanupManager


# Function 425: Runs unit tests for the cleanup_initialization functionality.
def test_cleanup_initialization():
    """Test that cleanup manager initializes with config."""
    config = {
        "cleanup": {"enabled": True, "interval": 3600, "retention_days": 7, "paths": "/tmp/logs"}
    }
    mgr = CleanupManager(config)
    assert mgr.enabled is True
    assert mgr.interval == 3600
    assert mgr.retention_days == 7
    assert mgr.target_paths == ["/tmp/logs"]


# Function 426: Runs unit tests for the cleanup_dry_run functionality.
def test_cleanup_dry_run(tmp_path):
    """Test dry run does not delete files."""
    # Create old file
    old_file = tmp_path / "old.log"
    old_file.write_text("content")

    # Set mtime to 10 days ago
    past = time.time() - (10 * 86400)
    os.utime(old_file, (past, past))

    config = {"cleanup": {"enabled": True, "retention_days": 7, "paths": str(tmp_path)}}
    mgr = CleanupManager(config)

    stats = mgr.cleanup_files(dry_run=True)

    assert old_file.exists()
    assert stats["deleted"] == 1  # dry run counts candidates
    # Wait, check implementation.
    # Logic: if not dry_run: file_path.unlink(); stats["deleted"] += 1.
    # So if dry_run, it still increments "deleted"?
    # Let's check source code I viewed earlier.
    # Line 59: if not dry_run: file_path.unlink();
    # Line 61: stats["deleted"] += 1
    # Yes, it counts them.


# Function 427: Runs unit tests for the cleanup_execution functionality.
def test_cleanup_execution(tmp_path):
    """Test actual deletion of old files."""
    # Create old file
    old_file = tmp_path / "old.log"
    old_file.write_text("content")
    past = time.time() - (10 * 86400)
    os.utime(old_file, (past, past))

    # Create new file
    new_file = tmp_path / "new.log"
    new_file.write_text("content")
    # mtime is now, so it should be kept

    config = {"cleanup": {"enabled": True, "retention_days": 7, "paths": str(tmp_path)}}
    mgr = CleanupManager(config)

    stats = mgr.cleanup_files(dry_run=False)

    assert not old_file.exists()
    assert new_file.exists()
    assert stats["deleted"] == 1
    assert stats["bytes_freed"] > 0
