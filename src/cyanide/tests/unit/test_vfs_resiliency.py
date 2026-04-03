from cyanide.vfs.profile_loader import invalidate, load


def test_sqlite_corruption_fallback(tmp_path):
    profile_dir = tmp_path / "profiles"
    ubuntu_dir = profile_dir / "ubuntu"
    ubuntu_dir.mkdir(parents=True)

    (ubuntu_dir / "static.yaml").write_text("static: {'/test.txt': {'content': 'OK'}}")
    (ubuntu_dir / "base.yaml").write_text("metadata: {os_id: ubuntu}")

    load("ubuntu", profile_dir)
    db_file = ubuntu_dir / ".compiled.db"
    assert db_file.exists()

    db_file.write_text("NOT_A_SQLITE_FILE")

    invalidate()
    data = load("ubuntu", profile_dir)
    assert data["backend_path"] == str(db_file)
    assert db_file.stat().st_size > 100
