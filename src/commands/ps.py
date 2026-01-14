from .base import Command

class PsCommand(Command):
    """Report a snapshot of the current processes."""

    def execute(self, args: list[str]) -> tuple[str, str, int]:
        """Execute the ps command.
        
        Returns:
            tuple: (process_list, empty_stderr, 0)
        """
        # Fake process list
        output = "    PID TTY          TIME CMD\n"
        output += f"   {1234} pts/0    00:00:00 bash\n"
        output += f"   {1235} pts/0    00:00:00 ps\n"
        return output, "", 0
