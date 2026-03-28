import asyncio

from .base import Command


class PwdCommand(Command):
    """Print the name of the current working directory."""

    # Function 258: Executes the 'pwd' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the pwd command.

        Returns:
            tuple: (current_working_directory, empty_stderr, 0)
        """
        return f"{self.emulator.cwd}\n", "", 0
