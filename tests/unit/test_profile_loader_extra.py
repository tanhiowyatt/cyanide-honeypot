import sqlite3

import pytest
import yaml

from cyanide.vfs.profile_loader import (
    _compile_to_sqlite,
    _flatten_nodes,
    _parse_yaml_profile,
    _scan_filesystem,
    invalidate,
    load,
)


@pytest.fixture
def temp_profile_dir(tmp_path):
    profile_dir = tmp_path / "test_profile"
    profile_dir.mkdir()
    return profile_dir


def test_scan_filesystem(temp_profile_dir):
    # Create a small dummy rootfs
    rootfs = temp_profile_dir / "rootfs"
    rootfs.mkdir()
    (rootfs / "etc").mkdir()
    (rootfs / "etc/config.txt").write_text("dummy content")

    manifest = _scan_filesystem(rootfs)

    assert "/etc" in manifest
    assert manifest["/etc"]["type"] == "dir"
    assert "/etc/config.txt" in manifest
    assert manifest["/etc/config.txt"]["type"] == "file"
    assert manifest["/etc/config.txt"]["content"] == b"dummy content"


def test_flatten_nodes_edge_cases():
    nodes = {
        "etc": {
            "passwd": "root:x:0:0...",
            "network": ["interfaces", "hosts"],  # List case
            "ssh": {"sshd_config": {"content": "Port 22", "owner": "root"}},  # Dict with content
        }
    }
    flat = _flatten_nodes(nodes)

    assert "/etc/passwd" in flat
    assert flat["/etc/passwd"]["content"] == "root:x:0:0..."

    assert "/etc/network" in flat
    assert flat["/etc/network"]["type"] == "dir"
    assert "/etc/network/interfaces" in flat
    assert "/etc/network/hosts" in flat

    assert "/etc/ssh/sshd_config" in flat
    assert flat["/etc/ssh/sshd_config"]["content"] == "Port 22"
    assert flat["/etc/ssh/sshd_config"]["owner"] == "root"


def test_parse_yaml_profile_with_honeytokens(temp_profile_dir):
    base_yaml = temp_profile_dir / "base.yaml"
    base_data = {
        "metadata": {"os_name": "TestOS"},
        "honeytokens": ["/etc/shadow", "/root/flag.txt"],
        "static_files": {"tree_folders": "/etc /bin /usr"},
    }
    base_yaml.write_text(yaml.dump(base_data))

    static_yaml = temp_profile_dir / "static.yaml"
    static_data = {"static": {"/etc/issue": "Welcome"}}
    static_yaml.write_text(yaml.dump(static_data))

    result = _parse_yaml_profile(base_yaml, static_yaml)

    assert result["metadata"]["os_name"] == "TestOS"
    assert result["honeytokens"] == ["/etc/shadow", "/root/flag.txt"]
    assert "/etc" in result["static"]
    assert "/etc/issue" in result["static"]


def test_compile_to_sqlite(tmp_path):
    db_path = tmp_path / "test.db"
    manifest = {"/etc/passwd": {"type": "file", "content": "root...", "owner": "root"}}
    _compile_to_sqlite(manifest, db_path, "target_hash")

    assert db_path.exists()
    conn = sqlite3.connect(db_path)
    cursor = conn.execute("SELECT content FROM vfs WHERE path = '/etc/passwd'")
    row = cursor.fetchone()
    assert row[0] == b"root..."

    cursor = conn.execute("SELECT value FROM metadata WHERE key = 'hash'")
    assert cursor.fetchone()[0] == "target_hash"
    conn.close()


def test_load_nonexistent_profile(tmp_path):
    with pytest.raises(FileNotFoundError):
        load("ghost_profile", tmp_path)


def test_invalidate_cache():
    # Just ensure it doesn't crash and clears internal dict
    invalidate()
    invalidate("some_profile")
