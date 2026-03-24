from unittest.mock import ANY, Mock

import pytest

from cyanide.vfs.engine import FakeFilesystem


# Function 432: Performs operations related to fs.
@pytest.fixture
def fs():
    return FakeFilesystem()


# Function 433: Runs unit tests for the initial_state functionality.
def test_initial_state(fs):
    assert fs.exists("/")
    assert fs.is_dir("/")
    assert not fs.exists("/nonexistent")


# Function 434: Runs unit tests for the mkdir_p functionality.
def test_mkdir_p(fs):
    # Single level
    fs.mkdir_p("/test")
    assert fs.exists("/test")
    assert fs.is_dir("/test")

    # Recursive
    fs.mkdir_p("/a/b/c")
    assert fs.exists("/a")
    assert fs.exists("/a/b")
    assert fs.exists("/a/b/c")
    assert fs.is_dir("/a/b/c")

    # Permissions
    node = fs.get_node("/a/b/c")
    assert node.perm == "drwxr-xr-x"  # Default


# Function 435: Runs unit tests for the mkfile functionality.
def test_mkfile(fs):
    # File in root
    fs.mkfile("/file1.txt", content="hello")
    assert fs.exists("/file1.txt")
    assert fs.is_file("/file1.txt")
    assert fs.get_content("/file1.txt") == "hello"

    # File in subdir (should fail if parent missing? mkfile implementation creates parents? No, unchecked in code)
    # mkfile implementation:
    # parent = self.get_node(parent_path)
    # if parent ...

    # Needs existing parent
    fs.mkdir_p("/home")
    f = fs.mkfile("/home/user.txt", content="user data")
    assert fs.exists("/home/user.txt")
    assert f is not None

    # Missing parent returns None
    f = fs.mkfile("/missing/file.txt")
    assert f is None
    assert not fs.exists("/missing/file.txt")


# Function 436: Runs unit tests for the remove functionality.
def test_remove(fs):
    fs.mkdir_p("/dir/subdir")
    fs.mkfile("/dir/file.txt")

    # Remove file
    assert fs.remove("/dir/file.txt") is True
    assert not fs.exists("/dir/file.txt")

    # Remove empty dir
    assert fs.remove("/dir/subdir") is True
    assert not fs.exists("/dir/subdir")

    # Remove non-empty dir (remove implementation?)
    # Directory.remove_child just removes it from children dict.
    # It doesn't check for emptiness in the basic implementation provided in code?
    # Let's check remove implementation in FakeFilesystem:
    # return parent.remove_child(name)
    fs.mkdir_p("/dir/full")
    fs.mkfile("/dir/full/file.txt")
    assert fs.remove("/dir/full") is True
    assert not fs.exists("/dir/full")

    # Remove root - forbidden
    assert fs.remove("/") is False


# Function 437: Runs unit tests for the resolve functionality.
def test_resolve(fs):
    assert fs.resolve("/") == "/"
    assert fs.resolve("//") == "/"
    assert fs.resolve("/a/b") == "/a/b"
    assert fs.resolve("/a/../b") == "/b"
    assert fs.resolve("/a/./b") == "/a/b"
    assert (
        fs.resolve("relative") == "relative"
    )  # posixpath.normpath returns relative if input is relative


# Function 438: Runs unit tests for the list_dir functionality.
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


# Function 439: Runs unit tests for the audit_callback functionality.
def test_audit_callback():
    mock_cb = Mock()
    fs = FakeFilesystem(audit_callback=mock_cb)

    fs.mkfile("/audit.txt", content="secret")

    # Read triggers audit
    fs.get_content("/audit.txt")
    mock_cb.assert_called_with("read", "/audit.txt", ANY)

    # Delete triggers audit
    fs.remove("/audit.txt")
    mock_cb.assert_called_with("delete", "/audit.txt", ANY)


# Function 440: Runs unit tests for the permissions_storage functionality.
def test_permissions_storage(fs):
    fs.mkfile("/secret.txt", owner="root", perm="-rw-------")
    node = fs.get_node("/secret.txt")
    assert node.owner == "root"
    assert node.perm == "-rw-------"
