import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def emulator():
    fs = FakeFilesystem()
    # Emulate root user session
    return ShellEmulator(fs, username="root")


@pytest.mark.asyncio
async def test_python_interactive(emulator):
    # Enter interactive python
    out, err, rc = await emulator.execute("python")
    assert rc == 0
    assert "Python 3.10" in out
    assert emulator.pending_input_prompt == ">>> "
    assert emulator.pending_input_callback is not None

    # Try a simple command
    out, err, rc = await emulator.execute("help")
    assert "interactive help" in out
    assert emulator.pending_input_prompt == ">>> "

    # Random code
    out, err, rc = await emulator.execute("import sys")
    assert emulator.pending_input_prompt == ">>> "

    out, err, rc = await emulator.execute("invalidname")
    assert "NameError: name 'invalidname' is not defined" in out

    # Exit
    out, err, rc = await emulator.execute("exit()")
    assert emulator.pending_input_callback is None


@pytest.mark.asyncio
async def test_editor_functionality(emulator):
    # Ensure /root exists
    emulator.fs.mkdir_p("/root", owner="root")

    out, err, rc = await emulator.execute("vi /root/test_script.sh")
    assert rc == 0
    assert "Entering editor" in out
    assert emulator.pending_input_callback is not None

    # Write lines
    await emulator.execute("echo 'Hello World'")
    await emulator.execute("exit 0")

    # Save and exit
    out, err, rc = await emulator.execute(":wq")
    assert "written" in out
    assert emulator.pending_input_callback is None

    # Check file content
    content = emulator.fs.get_content("/root/test_script.sh")
    assert content == "echo 'Hello World'\nexit 0\n"


@pytest.mark.asyncio
async def test_crontab_functionality(emulator):
    # Add new cron job
    out, err, rc = await emulator.execute("crontab -e")
    assert rc == 0
    assert "Entering crontab editor" in out
    assert emulator.pending_input_callback is not None

    # Write lines
    await emulator.execute("* * * * * /tmp/owned.sh")

    # Save
    out, err, rc = await emulator.execute("DONE")
    assert emulator.pending_input_callback is None
    assert "installing new crontab" in out

    # Check what is listed
    out, err, rc = await emulator.execute("crontab -l")
    assert rc == 0
    assert "* * * * * /tmp/owned.sh" in out

    # Remove
    out, err, rc = await emulator.execute("crontab -r")
    assert rc == 0

    # Empty list
    out, err, rc = await emulator.execute("crontab -l")
    assert "no crontab for" in out
