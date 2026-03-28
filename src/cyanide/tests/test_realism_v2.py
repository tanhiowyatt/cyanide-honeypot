import asyncio
import shutil
from pathlib import Path

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


async def test_realism_v2():
    # Cleanup history
    history_dir = Path("var/lib/cyanide/history")
    if history_dir.exists():
        shutil.rmtree(history_dir)

    src_ip = "1.2.3.4"

    # Session 1
    print("--- Session 1 ---")
    fs1 = FakeFilesystem(src_ip=src_ip, session_id="s1")
    emulator1 = ShellEmulator(fs1, username="root", src_ip=src_ip, session_id="s1")

    # 1. Test backgrounding
    print("Testing backgrounding (&)...")
    await emulator1.execute("sleep 100 &")
    stdout, _, _ = await emulator1.execute("ps aux")
    if "sleep 100" in stdout:
        print("SUCCESS: Background process found in ps aux")
    else:
        print("FAIL: Background process NOT found in ps aux")
        return False

    # 2. Test history creation
    print("Testing history persistence...")
    # Simulate writing to .bash_history (ShellEmulator would do this on input normally,
    # but let's just mkfile it to be sure it's in the overlay)
    fs1.mkfile("/root/.bash_history", "ls\nwhoami\nsleep 100 &\n")
    fs1.save_ip_history()

    if (history_dir / src_ip / ".bash_history").exists():
        print("SUCCESS: History file saved to disk")
    else:
        print("FAIL: History file NOT saved to disk")
        return False

    # Session 2 (Return from same IP)
    print("\n--- Session 2 (Reconnect) ---")
    fs2 = FakeFilesystem(src_ip=src_ip, session_id="s2")
    if fs2.exists("/root/.bash_history"):
        content = fs2.get_content("/root/.bash_history")
        if "ls" in content and "sleep 100" in content:
            print("SUCCESS: History persisted to new session")
        else:
            print(f"FAIL: History content mismatch: {repr(content)}")
            return False
    else:
        print("FAIL: History file NOT found in new session")
        return False

    # 3. Test Pacman
    print("\nTesting pacman...")
    stdout, _, rc = await emulator1.execute("pacman -S nmap")
    if rc == 0 and "installing nmap" in stdout and fs1.exists("/usr/bin/nmap"):
        print("SUCCESS: Pacman emulated correctly and created binary")
    else:
        print("FAIL: Pacman emulation failed")
        return False

    return True


if __name__ == "__main__":
    if asyncio.run(test_realism_v2()):
        print("\nALL REALISM V2 TESTS PASSED")
    else:
        print("\nREALISM V2 TESTS FAILED")
        exit(1)
