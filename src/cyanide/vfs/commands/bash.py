from typing import cast

from .base import Command


class BashCommand(Command):
    """Simple bash interpreter command."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        if not args:
            return "", "", 0

        # Filter out common interactive/login flags
        clean_args = [a for a in args if not a.startswith("-") or a == "-c"]

        if "-i" in args:
            return "welcome to cyanide bash\n", "", 0

        if not clean_args and args:
            # Just flags like -l
            return "", "", 0

        script_path = clean_args[0] if clean_args else args[0]
        # if it's -c, the next arg is the command string
        if script_path == "-c" and len(clean_args) > 1:
            res = await self.emulator.execute(clean_args[1])
            return cast(tuple[str, str, int], res)

        abs_path = self.emulator.resolve_path(script_path)

        if not self.fs.exists(abs_path):
            return "", f"bash: {script_path}: No such file or directory\n", 127

        if self.fs.is_dir(abs_path):
            return "", f"bash: {script_path}: Is a directory\n", 126

        content = self.get_content_str(abs_path)

        self._log_event(
            "bash_script_execution",
            {
                "path": script_path,
                "lines_count": len(content.splitlines()),
                "content_preview": content[:200],
            },
        )

        lines = content.splitlines()
        full_stdout = ""
        full_stderr = ""
        last_rc = 0

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            stdout, stderr, rc = await self.emulator.execute(line)
            full_stdout += stdout
            full_stderr += stderr
            last_rc = rc

        return full_stdout, full_stderr, last_rc
