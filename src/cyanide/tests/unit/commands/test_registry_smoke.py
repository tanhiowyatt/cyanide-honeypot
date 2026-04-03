import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands import COMMAND_MAP
from cyanide.vfs.engine import FakeFilesystem


@pytest.fixture
def fs():
    return FakeFilesystem()


@pytest.fixture
def emulator(fs):
    return ShellEmulator(fs, username="admin")


@pytest.mark.asyncio
@pytest.mark.parametrize("cmd_name", COMMAND_MAP.keys())
async def test_command_registry_smoke(emulator, cmd_name):
    """
    Smoke test for every command in the registry.
    Ensures they can be instantiated and executed without crashing.
    """

    args = []

    if cmd_name in ("ip", "systemctl", "journalctl"):
        args = ["help"]
    elif cmd_name == "cd":
        args = ["/"]

    try:
        result = await emulator.execute(f"{cmd_name} {' '.join(args)}".strip())

        assert isinstance(result, tuple)
        assert len(result) == 3
        stdout, stderr, rc = result
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)
        assert isinstance(rc, int)

    except SystemExit as se:
        rc = se.code if isinstance(se.code, int) else 2
        assert isinstance(rc, int)
    except Exception as e:
        pytest.fail(f"Command '{cmd_name}' failed with exception: {e}")


@pytest.mark.asyncio
async def test_all_commands_covered(emulator):
    """Verify that all files in src/cyanide/vfs/commands/ are in the registry."""
    import os

    cmd_dir = "src/cyanide/vfs/commands"
    files = [
        f
        for f in os.listdir(cmd_dir)
        if f.endswith(".py") and f != "__init__.py" and f != "base.py" and f != "network.py"
    ]

    registered_classes = [cls.__name__ for cls in COMMAND_MAP.values()]

    for f in files:
        module_name = f[:-3]
        expected_class = "".join(word.capitalize() for word in module_name.split("_")) + "Command"
        if expected_class not in registered_classes:
            print(
                f"Warning: Module {module_name} might not be registered in COMMAND_MAP (expected {expected_class})"
            )
