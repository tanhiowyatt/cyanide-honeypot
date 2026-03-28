import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.awk import AwkCommand


# Function 348: Performs operations related to shell.
@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


# Function 349: Runs unit tests for the awk_basic_print functionality.
@pytest.mark.asyncio
async def test_awk_basic_print(shell):
    cmd = AwkCommand(shell)
    input_data = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"

    # Print first field with colon separator
    stdout, stderr, rc = await cmd.execute(["-F:", "{print $1}"], input_data=input_data)
    assert rc == 0
    assert stdout == "root\ndaemon\n"


# Function 350: Runs unit tests for the awk_multiple_fields functionality.
@pytest.mark.asyncio
async def test_awk_multiple_fields(shell):
    cmd = AwkCommand(shell)
    input_data = "field1 field2 field3\nval1 val2 val3"

    # Print first and third fields (default space separator)
    stdout, stderr, rc = await cmd.execute(["{print $1, $3}"], input_data=input_data)
    assert rc == 0
    assert stdout == "field1 field3\nval1 val3\n"


# Function 351: Runs unit tests for the awk_print_all functionality.
@pytest.mark.asyncio
async def test_awk_print_all(shell):
    cmd = AwkCommand(shell)
    input_data = "line one\nline two"

    # Print $0 (whole line)
    stdout, stderr, rc = await cmd.execute(["{print $0}"], input_data=input_data)
    assert rc == 0
    assert stdout == "line one\nline two\n"


# Function 352: Runs unit tests for the awk_file_input functionality.
@pytest.mark.asyncio
async def test_awk_file_input(shell, mock_fs):
    cmd = AwkCommand(shell)
    mock_fs.mkfile("/root/test.txt", content="a:b:c\nd:e:f")

    stdout, stderr, rc = await cmd.execute(["-F:", "{print $2}", "test.txt"])
    assert rc == 0
    assert stdout == "b\ne\n"


# Function 353: Runs unit tests for the awk_unsupported_script functionality.
@pytest.mark.asyncio
async def test_awk_unsupported_script(shell):
    cmd = AwkCommand(shell)
    # If script format is not recognized, it should return empty output but not fail (simplification)
    stdout, stderr, rc = await cmd.execute(["BEGIN {print 'hi'}"], input_data="data")
    assert rc == 0
    assert stdout == ""
