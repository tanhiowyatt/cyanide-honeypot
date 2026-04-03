from unittest.mock import ANY, Mock

import pytest

from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def fs():
    return FakeFilesystem()


def test_initial_state(fs):
    assert fs.exists("/")
    assert fs.is_dir("/")
    assert not fs.exists("/nonexistent")


def test_mkdir_p(fs):
    fs.mkdir_p("/test")
    assert fs.exists("/test")
    assert fs.is_dir("/test")

    fs.mkdir_p("/a/b/c")
    assert fs.exists("/a")
    assert fs.exists("/a/b")
    assert fs.exists("/a/b/c")
    assert fs.is_dir("/a/b/c")

    node = fs.get_node("/a/b/c")
    assert node.perm == "drwxr-xr-x"


def test_mkfile(fs):
    fs.mkfile("/file1.txt", content="hello")
    assert fs.exists("/file1.txt")
    assert fs.is_file("/file1.txt")
    assert fs.get_content("/file1.txt") == "hello"

    fs.mkdir_p("/home")
    f = fs.mkfile("/home/user.txt", content="user data")
    assert fs.exists("/home/user.txt")
    assert f is not None

    f = fs.mkfile("/missing/file.txt")
    assert f is None
    assert not fs.exists("/missing/file.txt")


def test_remove(fs):
    fs.mkdir_p("/dir/subdir")
    fs.mkfile("/dir/file.txt")

    assert fs.remove("/dir/file.txt") is True
    assert not fs.exists("/dir/file.txt")

    assert fs.remove("/dir/subdir") is True
    assert not fs.exists("/dir/subdir")

    fs.mkdir_p("/dir/full")
    fs.mkfile("/dir/full/file.txt")
    assert fs.remove("/dir/full") is True
    assert not fs.exists("/dir/full")

    assert fs.remove("/") is False


def test_resolve(fs):
    assert fs.resolve("/") == "/"
    assert fs.resolve("//") == "/"
    assert fs.resolve("/a/b") == "/a/b"
    assert fs.resolve("/a/../b") == "/b"
    assert fs.resolve("/a/./b") == "/a/b"
    assert (
        fs.resolve("relative") == "relative"
    )  # posixpath.normpath returns relative if input is relative


def test_list_dir(fs):
    fs.mkdir_p("/list")
    fs.mkfile("/list/a.txt")
    fs.mkfile("/list/b.txt")
    fs.mkdir_p("/list/subdir")

    items = fs.list_dir("/list")
    assert "a.txt" in items
    assert "b.txt" in items
    assert "subdir" in items
    assert len(items) == 3

    # nonexistent
    assert fs.list_dir("/nothing") == []


def test_audit_callback():
    mock_cb = Mock()
    fs = FakeFilesystem(audit_callback=mock_cb)

    fs.mkfile("/audit.txt", content="secret")

    fs.get_content("/audit.txt")
    mock_cb.assert_called_with("read", "/audit.txt", ANY)

    fs.remove("/audit.txt")
    mock_cb.assert_called_with("delete", "/audit.txt", ANY)


def test_permissions_storage(fs):
    fs.mkfile("/secret.txt", owner="root", perm="-rw-------")
    node = fs.get_node("/secret.txt")
    assert node.owner == "root"
    assert node.perm == "-rw-------"
