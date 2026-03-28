from cyanide.vfs.profile_loader import invalidate, load


def test_sqlite_corruption_fallback(tmp_path):
    # Setup: Create a profile-like structure
    profile_dir = tmp_path / "profiles"
    ubuntu_dir = profile_dir / "ubuntu"
    ubuntu_dir.mkdir(parents=True)

    # Create valid YAML
    (ubuntu_dir / "static.yaml").write_text("static: {'/test.txt': {'content': 'OK'}}")
    (ubuntu_dir / "base.yaml").write_text("metadata: {os_id: ubuntu}")

    # Pre-compile
    load("ubuntu", profile_dir)
    db_file = ubuntu_dir / ".compiled.db"
    assert db_file.exists()

    # 1. Corrupt the SQLite file
    db_file.write_text("NOT_A_SQLITE_FILE")

    # 2. Try to load again
    invalidate()
    data = load("ubuntu", profile_dir)

    # 3. Verify it fell back to YAML and regenerated
    assert data["backend_path"] == str(db_file)
    assert db_file.stat().st_size > 100  # Should be valid SQLite now
