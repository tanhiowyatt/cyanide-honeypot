from .base import Command

class UnameCommand(Command):
    """Print system information."""

    def execute(self, args: list[str]) -> tuple[str, str, int]:
        """Execute the uname command.
        
        Args:
             args: Flags (e.g., -a).
             
        Returns:
             tuple: (system_info, empty_stderr, 0)
        """
        if not args:
            return "Linux\n", "", 0
            
        if "-a" in args or "--all" in args:
            return "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n", "", 0
            
        if "-r" in args:
            return "5.15.0-91-generic\n", "", 0
            
        if any(arg.startswith("-") for arg in args):
             # Simple error for now if not handled
             invalid_flag = next(arg for arg in args if arg.startswith("-") and arg not in ["-a", "-r"])
             flag_char = invalid_flag.replace("-", "")[0]
             return "", f"uname: invalid option -- '{flag_char}'\nTry 'uname --help' for more information.\n", 1
             
        # Ignore non-flag args or treat as invalid? standard uname ignores extra args? 
        # Actually `uname` takes no non-option arguments.
        # "uname: extra operand 'foo'"
        return "Linux\n", "", 0
