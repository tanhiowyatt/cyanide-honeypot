import asyncio

from .base import Command


class EchoCommand(Command):
    """Display a line of text."""

    # Function 226: Executes the 'echo' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the echo command.

        Args:
            args: Strings to display.

        Returns:
            tuple: (joined_args, empty_stderr, 0)
        """
        return " ".join(args) + "\n", "", 0
