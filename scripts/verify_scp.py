import asyncio
import os
import asyncssh
import tempfile
from pathlib import Path

# Test configurations
HOST = "127.0.0.1"
PORT = 2222
USERS = [
    ("root", "admin"),
    ("admin", "admin"),
    ("user", "123456"),
]
TARGET_DIRS = [
    "/root",
    "/tmp",
    "/home/admin",
    "/home/user",
]

# Writable temporary directory on volume
TEMP_BASE = "/app/var/lib/cyanide/tmp"
os.makedirs(TEMP_BASE, exist_ok=True)

async def test_upload_download(username, password, target_dir):
    filename = f"verify_scp_{username}_{target_dir.replace('/', '_')}.txt"
    content = f"Verification content for {username} in {target_dir} - {os.urandom(4).hex()}"
    
    with tempfile.TemporaryDirectory(dir=TEMP_BASE) as tmpdir:
        local_upload_path = str(Path(tmpdir) / filename)
        local_download_path = str(Path(tmpdir) / "downloaded_file.txt")
        
        with open(local_upload_path, "w") as f:
            f.write(content)
        
        try:
            async with asyncssh.connect(
                HOST, port=PORT, username=username, password=password, known_hosts=None
            ) as conn:
                remote_path = f"{target_dir}/{filename}"
                print(f"[*] Testing {username} -> {remote_path}...", end=" ")
                
                # Upload (to the directory)
                try:
                    await asyncssh.scp(local_upload_path, (conn, target_dir))
                except Exception as e:
                    print(f"UPLOAD FAILED ({e})")
                    return False
                
                # Download
                try:
                    await asyncssh.scp((conn, remote_path), local_download_path)
                except Exception as e:
                    print(f"DOWNLOAD FAILED ({e})")
                    # Debug: List the directory to see where the file is
                    ls_res = await conn.run(f"ls -la {target_dir}", check=False)
                    print(f"DEBUG {target_dir} content:\n{ls_res.stdout}")
                    return False
                
                # Verify
                try:
                    with open(local_download_path, "r") as f:
                        downloaded = f.read()
                    if downloaded == content:
                        print("PASSED")
                        return True
                    else:
                        print("FAILED (Content mismatch)")
                        return False
                except Exception as e:
                    print(f"VERIFY FAILED ({e})")
                    return False
        except Exception as e:
            print(f"CONN FAILED ({e})")
            return False

async def main():
    print(f"[*] Starting SCP Verification against {HOST}:{PORT}")
    results = []
    for username, password in USERS:
        for target_dir in TARGET_DIRS:
            res = await test_upload_download(username, password, target_dir)
            results.append(res)
    
    passed = sum(results)
    total = len(results)
    print(f"\n[*] Summary: {passed}/{total} tests passed.")
    if passed == total:
        exit(0)
    else:
        exit(1)

if __name__ == "__main__":
    asyncio.run(main())
