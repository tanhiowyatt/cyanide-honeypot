import time

from .base import Command


class WhoCommand(Command):
    """Show who is logged on."""

    # Function 277: Executes the 'who' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the who command.

        Returns:
            tuple: (user_list, empty_stderr, 0)
        """
        now = time.strftime("%Y-%m-%d %H:%M")
        return (
            f"root     pts/0        {now} (192.168.1.50)\nadmin    pts/1        {now} (10.0.0.2)\n",
            "",
            0,
        )
