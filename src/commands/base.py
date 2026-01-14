
class Command:
    """Base class for shell commands."""
    
    def __init__(self, emulator):
        self.emulator = emulator
        self.fs = emulator.fs
        self.username = emulator.username

    def execute(self, args: list[str]) -> tuple[str, str, int]:
        """Execute the command.
        
        Args:
            args: Command arguments (excluding command name).
            
        Returns:
            tuple: (stdout, stderr, return_code)
        """
        raise NotImplementedError
