import asyncio

from .base import Command


class UnameCommand(Command):
    """Print system information."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the uname command.

        Args:
             args: Flags (e.g., -a).

        Returns:
             tuple: (system_info, empty_stderr, 0)
        """
        profile = getattr(self.fs, "profile", None)
        uname_a = "Linux server 5.15.0-91-generic..."
        uname_r = "5.15.0-91-generic"

        if profile:
            uname_a = profile.get("uname_a", uname_a)
            uname_r = profile.get("uname_r", uname_r)

        if not args:
            return "Linux\n", "", 0

        if "-a" in args or "--all" in args:
            return f"{uname_a}\n", "", 0

        if "-r" in args:
            return f"{uname_r}\n", "", 0

        if any(arg.startswith("-") for arg in args):
            invalid_flag = next(
                arg for arg in args if arg.startswith("-") and arg not in ["-a", "-r"]
            )
            flag_char = invalid_flag.replace("-", "")[0]
            return (
                "",
                f"uname: invalid option -- '{flag_char}'\nTry 'uname --help' for more information.\n",
                1,
            )

        return "Linux\n", "", 0
