from .base import Command

class PwdCommand(Command):
    """Print the name of the current working directory."""

    def execute(self, args: list[str]) -> tuple[str, str, int]:
        """Execute the pwd command.
        
        Returns:
            tuple: (current_working_directory, empty_stderr, 0)
        """
        return f"{self.emulator.cwd}\n", "", 0
