import asyncio

from .base import Command


class WhoamiCommand(Command):
    """Print the user name associated with the current effective user ID."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the whoami command.

        Returns:
            tuple: (username, empty_stderr, 0)
        """
        return f"{self.emulator.username}\n", "", 0
