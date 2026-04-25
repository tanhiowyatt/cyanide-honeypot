import pytest

from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def fs():
    return FakeFilesystem()


def test_fs_chown(fs):
    fs.mkfile("/test.txt", owner="root", group="root")
    assert fs.get_owner("/test.txt") == "root"

    fs.chown("/test.txt", owner="user1", group="group1")
    node = fs.get_node("/test.txt")
    assert node.owner == "user1"
    assert node.group == "group1"

    # Test chown on directory
    fs.mkdir_p("/dir1")
    fs.chown("/dir1", owner="www-data")
    assert fs.get_owner("/dir1") == "www-data"


def test_fs_chmod(fs):
    fs.mkfile("/test.txt", perm="-rw-r--r--")
    fs.chmod("/test.txt", "-rwxr-xr-x")
    assert fs.get_node("/test.txt").perm == "-rwxr-xr-x"

    # Test chmod on directory
    fs.mkdir_p("/dir1", perm="drwxr-xr-x")
    fs.chmod("/dir1", "drwx------")
    assert fs.get_node("/dir1").perm == "drwx------"


def test_fs_copy_move(fs):
    fs.mkfile("/src.txt", content="hello")

    # Simple copy
    fs.copy("/src.txt", "/dst.txt")
    assert fs.exists("/dst.txt")
    assert fs.get_content("/dst.txt") == "hello"

    # Recursive copy
    fs.mkdir_p("/src_dir")
    fs.mkfile("/src_dir/f1.txt", content="f1")
    fs.copy("/src_dir", "/dst_dir", recursive=True)
    assert fs.exists("/dst_dir/f1.txt")
    assert fs.get_content("/dst_dir/f1.txt") == "f1"

    # Move
    fs.move("/dst.txt", "/moved.txt")
    assert not fs.exists("/dst.txt")
    assert fs.exists("/moved.txt")
    assert fs.get_content("/moved.txt") == "hello"


def test_fs_resolve(fs):
    assert fs.resolve("") == "/"
    assert fs.resolve("///") == "/"
    assert fs.resolve("//etc/passwd") == "/etc/passwd"
    assert fs.resolve("/etc/../etc/passwd") == "/etc/passwd"


def test_fs_is_file_is_dir(fs):
    fs.mkdir_p("/dir")
    fs.mkfile("/dir/file")

    assert fs.is_dir("/dir")
    assert not fs.is_file("/dir")
    assert fs.is_file("/dir/file")
    assert not fs.is_dir("/dir/file")

    fs.remove("/dir/file")
    assert not fs.exists("/dir/file")
    assert not fs.is_file("/dir/file")
