from .base import Command

class HelpCommand(Command):
    """Display information about builtin commands."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the help command.
        
        Returns:
            tuple: (help_text, empty_stderr, 0)
        """
        return "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\nThese shell commands are defined internally.  Type `help' to see this list.\n", "", 0
