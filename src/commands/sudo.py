from .base import Command

class SudoCommand(Command):
    """Execute a command as another user (mock)."""

    def execute(self, args: list[str]) -> tuple[str, str, int]:
        """Execute the sudo command (mock logic).
        
        Args:
             args: Command to execute with privileges.
             
        Returns:
             tuple: (stdout, stderr, return_code) - always fails with password error in this mock.
        """
        return "", f"[sudo] password for {self.username}: \nSorry, try again.\n[sudo] password for {self.username}: \nsudo: 3 incorrect password attempts\n", 1
