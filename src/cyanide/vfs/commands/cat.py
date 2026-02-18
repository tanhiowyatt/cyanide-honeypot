from .base import Command


class CatCommand(Command):
    """Concatenate content of files and print to standard output."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the cat command.

        Args:
            args: List of file paths.

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        if not args:
            return input_data or "", "", 0

        output = ""
        for arg in args:
            if "*" in arg:
                # Very basic wildcard handling for flag*
                if "flag" in arg:
                    # Look for flag in cwd
                    files = self.fs.list_dir(self.emulator.cwd)
                    for f in files:
                        if "flag" in f:
                            output += self.fs.get_content(f"{self.emulator.cwd}/{f}")
                continue

            path = self.emulator.resolve_path(arg)
            if self.fs.is_file(path):
                output += self.fs.get_content(path)
            elif self.fs.is_dir(path):
                return "", f"cat: {arg}: Is a directory\n", 1
            else:
                return "", f"cat: {arg}: No such file or directory\n", 1
        return output, "", 0
