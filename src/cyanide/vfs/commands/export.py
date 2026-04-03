import asyncio

from .base import Command


class ExportCommand(Command):
    """Set environment variables (mock)."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the export command.

        Note:
            This is a mock implementation that does nothing but return success,
            as SSH clients often send export commands on startup.

        Returns:
            tuple: (stdout, stderr, 0)
        """
        for arg in args:
            if "=" in arg:
                key, val = arg.split("=", 1)
                self.emulator.env[key] = val
        return "", "", 0
