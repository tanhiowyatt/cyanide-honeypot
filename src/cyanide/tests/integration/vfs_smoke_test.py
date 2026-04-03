import asyncio
import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent / "src"))

from cyanide.core.server import CyanideServer


async def smoke_test():
    config = {
        "os_profile": "ubuntu",
        "logging": {"directory": "var/log/cyanide"},
        "users": [{"user": "root", "pass": "root"}],
    }

    os.makedirs("var/log/cyanide", exist_ok=True)

    server = CyanideServer(config)
    fs = server.get_filesystem()

    from cyanide.core.emulator import ShellEmulator

    emulator = ShellEmulator(fs, username="root")

    print("--- Test: ls / ---")
    stdout, stderr, code = await emulator.execute("ls /")
    print(f"STDOUT: {stdout.strip()}")

    print("\n--- Test: cat /etc/issue ---")
    stdout, stderr, code = await emulator.execute("cat /etc/issue")
    print(f"STDOUT: {stdout.strip()}")

    print("\n--- Test: uptime ---")
    stdout, stderr, code = await emulator.execute("uptime")
    print(f"STDOUT: {stdout.strip()}")

    print("\n--- Test: Multiple Profiles (Debian) ---")
    server.os_profile = "debian"
    fs_debian = server.get_filesystem()
    emulator_debian = ShellEmulator(fs_debian, username="root")
    stdout, stderr, code = await emulator_debian.execute("cat /etc/issue")
    print(f"Debian STDOUT: {stdout.strip()}")


if __name__ == "__main__":
    asyncio.run(smoke_test())
