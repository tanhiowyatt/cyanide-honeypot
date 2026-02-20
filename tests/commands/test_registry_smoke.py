import pytest

from cyanide.core.emulator import ShellEmulator
from cyanide.vfs.commands import COMMAND_MAP
from cyanide.vfs.provider import FakeFilesystem


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
    # Some commands might need specific setups, but for a smoke test
    # we just check if they return the expected (stdout, stderr, rc) tuple.

    # We skip 'su' or 'pkexec' in this specific smoke test if they require interactive input
    # that blocks the async loop without a mock input provider, but most should be fine.

    # Use empty args or some safe defaults
    args = []

    # Pass 'help' to some commands that might error out on empty args
    if cmd_name in ("ip", "systemctl", "journalctl"):
        args = ["help"]
    elif cmd_name == "cd":
        args = ["/"]

    try:
        result = await emulator.execute(f"{cmd_name} {' '.join(args)}".strip())

        # Verify the return format
        assert isinstance(result, tuple)
        assert len(result) == 3
        stdout, stderr, rc = result
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)
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

    # This is a loose check to ensure we didn't forget to import a new file into __init__.py
    for f in files:
        module_name = f[:-3]
        # We don't necessarily enforce filename == command name, but most follow this pattern
        # Just check if we can find a class that looks like CommandNameCommand
        expected_class = "".join(word.capitalize() for word in module_name.split("_")) + "Command"
        # Some are special cases like 'ls' -> 'LsCommand'
        if expected_class not in registered_classes:
            # Basic warning if a file exists but isn't obviously registered
            print(
                f"Warning: Module {module_name} might not be registered in COMMAND_MAP (expected {expected_class})"
            )
