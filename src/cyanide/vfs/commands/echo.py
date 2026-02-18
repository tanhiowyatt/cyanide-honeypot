from .base import Command


class EchoCommand(Command):
    """Display a line of text."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the echo command.

        Args:
            args: Strings to display.

        Returns:
            tuple: (joined_args, empty_stderr, 0)
        """
        return " ".join(args) + "\n", "", 0
