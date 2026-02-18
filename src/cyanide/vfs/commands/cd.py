from .base import Command

class CdCommand(Command):
    """Change the current working directory."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the cd command.
        
        Args:
            args: Target directory path.
            
        Returns:
            tuple: (stdout, stderr, return_code)
        """
        if not args:
            target = "/root" if self.username == "root" else f"/home/{self.username}"
        else:
            target = self.emulator.resolve_path(args[0])
        
        if self.fs.is_dir(target):
            self.emulator.cwd = target
            return "", "", 0
        elif self.fs.exists(target):
            return "", f"bash: cd: {args[0]}: Not a directory\n", 1
        return "", f"bash: cd: {args[0]}: No such file or directory\n", 1
