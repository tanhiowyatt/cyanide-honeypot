import asyncio
import yaml
from cyanide.vfs.provider import FakeFilesystem
from cyanide.core.emulator import ShellEmulator

async def verify_profile(profile_path, expected_pretty_name, expected_id, expected_year):
    print(f"\n===== Testing {profile_path} =====")
    with open(profile_path, "r") as f:
        full_profile = yaml.safe_load(f)
    
    metadata = full_profile.get("metadata", full_profile)
    from cyanide.vfs.nodes import Directory
    root_node = Directory.from_dict(full_profile)
    
    fs = FakeFilesystem(root=root_node, profile=metadata)
    emulator = ShellEmulator(fs)
    
    print(f"--- 1. Testing /etc/os-release ---")
    stdout, _, _ = await emulator.execute("cat /etc/os-release")
    print(stdout)
    assert f'PRETTY_NAME="{expected_pretty_name}"' in stdout
    assert f'ID={expected_id}' in stdout
    
    print("--- 2. Testing ps aux ---")
    stdout, _, _ = await emulator.execute("ps aux")
    # print(stdout)
    assert "/sbin/init" in stdout or "systemd" in stdout
    
    print("--- 3. Testing Timestamps ---")
    etc_node = fs.get_node("/etc")
    print(f" /etc mtime: {etc_node.mtime}")
    assert etc_node.mtime.year == expected_year
    
    print("--- 4. Testing /proc dynamic files ---")
    stdout1, _, _ = await emulator.execute("cat /proc/uptime")
    assert stdout1 != ""

async def verify():
    await verify_profile("configs/profiles/fs.ubuntu_22_04.yaml", "Ubuntu 22.04.3 LTS (Jammy Jellyfish)", "ubuntu", 2023)
    await verify_profile("configs/profiles/fs.debian_11.yaml", "Debian GNU/Linux 11 (bullseye)", "debian", 2024)
    await verify_profile("configs/profiles/fs.centos_7.yaml", "CentOS Linux 7 (Core)", "centos", 2024)

if __name__ == "__main__":
    asyncio.run(verify())
