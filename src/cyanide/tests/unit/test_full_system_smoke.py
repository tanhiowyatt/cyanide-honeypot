import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def emulator():
    fs = FakeFilesystem()
    # Add some initial structure
    fs.mkdir_p("/etc")
    fs.mkfile("/etc/passwd", content="root:x:0:0:root:/root:/bin/bash")
    fs.mkdir_p("/var/log")
    config = {"profile": "debian", "users": [{"user": "root", "pass": "cyanide"}]}
    return ShellEmulator(fs, username="root", config=config)


@pytest.mark.asyncio
async def test_mega_bash_smoke_test(emulator):
    # This script touches almost all command categories
    mega_script = r"""
# 1. Navigation and FS
pwd
mkdir /tmp/smoke_test
cd /tmp/smoke_test
touch file1.txt
echo "cyanide test" > file2.txt
cp file2.txt file3.txt
mv file3.txt file4.txt
ls -la
rm file1.txt

# 2. Content processing
cat file2.txt | grep cyanide
echo "line1\nline2\nline3" > lines.txt
head -n 1 lines.txt
tail -n 1 lines.txt
awk '{print $1}' file2.txt

# 3. System Info
id
whoami
uptime
uname -a
free -m
df -h
ps aux

# 4. Networking
ifconfig
ip addr
netstat -ant
ss -l
ping -c 1 8.8.8.8
# curl/wget (mocked behavior)
curl -I http://google.com
wget -q -O - http://example.com

# 5. Admin & Packages
chmod 777 file4.txt
# sudo/doas mock
sudo whoami
doas id
# Package managers
apt-get update
dpkg -l
yum list
rpm -qa

# 6. Development Tools
python3 --version
perl -e 'print "hello"'
# Mock gcc/make
echo "int main(){return 0;}" > test.c
gcc test.c -o test_bin
make --version

# 7. Misc
history
date
crontab -l
    """

    # Save and run
    emulator.fs.mkfile("/root/smoke.sh", content=mega_script, perm="-rwxr-xr-x")
    stdout, stderr, rc = await emulator.execute("/root/smoke.sh")

    # Validation: Ensure basic markers are in output
    assert "/root" in stdout
    assert "cyanide test" in stdout
    assert "root" in stdout
    assert "127.0.0.1" in stdout or "eth0" in stdout
    assert "python" in stdout.lower()

    # Check new commands
    assert "UTC" in stdout  # date
    assert "Filesystem" in stdout  # df

    # We allow some stderr for things like 'make' with no targets
    # but we check if the overall return code is successful (or reasonable)
    assert rc == 0 or rc == 2  # make often returns 2 on error
