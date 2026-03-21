from unittest.mock import patch

from cyanide.core.fs_utils import get_fs_config_dir, list_profiles, resolve_os_profile


def test_get_fs_config_dir():
    with patch("pathlib.Path.exists", return_value=True):
        res = get_fs_config_dir()
        assert "profiles" in str(res)


def test_list_profiles_empty():
    with patch("pathlib.Path.exists", return_value=False):
        assert list_profiles() == ["ubuntu"]


def test_list_profiles_with_data(tmp_path):
    # Mocking filesystem structure
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    ubuntu_dir = profile_dir / "ubuntu"
    ubuntu_dir.mkdir()
    (ubuntu_dir / "base.yaml").write_text("dummy")

    with patch("cyanide.core.fs_utils.get_fs_config_dir", return_value=profile_dir):
        profiles = list_profiles()
        assert "ubuntu" in profiles


def test_resolve_os_profile():
    with patch("cyanide.core.fs_utils.list_profiles", return_value=["ubuntu", "centos"]):
        assert resolve_os_profile("ubuntu") == "ubuntu"
        assert resolve_os_profile("random") in ["ubuntu", "centos"]
        assert resolve_os_profile("nonexistent") == "ubuntu"
