import asyncio

from .base import Command


class CatCommand(Command):
    """Concatenate content of files and print to standard output."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the cat command."""
        if not args:
            return input_data or "", "", 0

        total_output = ""
        for arg in args:
            if "*" in arg:
                total_output += self._handle_wildcard(arg)
                continue

            stdout, stderr, rc = self._handle_file(arg)
            if rc != 0:
                return stdout, stderr, rc
            total_output += stdout

        return total_output, "", 0

    def _handle_wildcard(self, arg: str) -> str:
        """Handle wildcard expansion (specifically for 'flag' in this honeypot)."""
        output = ""
        if "flag" in arg:
            files = self.fs.list_dir(self.emulator.cwd)
            for f in files:
                if "flag" in f:
                    output += self.fs.get_content(f"{self.emulator.cwd}/{f}")
        return output

    def _handle_file(self, arg: str) -> tuple[str, str, int]:
        """Handle a single file path."""
        path = self.emulator.resolve_path(arg)
        if self.fs.is_file(path):
            return self.fs.get_content(path), "", 0
        if self.fs.is_dir(path):
            return "", f"cat: {arg}: Is a directory\n", 1
        return "", f"cat: {arg}: No such file or directory\n", 1
