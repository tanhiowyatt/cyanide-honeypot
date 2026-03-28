import asyncio
import time

from .base import Command


class WCommand(Command):
    """Show who is logged on and what they are doing."""

    # Function 275: Executes the 'w' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the w command.

        Returns:
            tuple: (uptime_and_users_stats, empty_stderr, 0)
        """
        now = time.strftime("%H:%M:%S")
        return (
            f" {now} up 12 days, 14:10,  2 users,  load average: 0.01, 0.03, 0.00\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    192.168.1.50     09:00    1.00s  0.10s  0.00s w\nadmin    pts/1    10.0.0.2         10:30    2:00   0.05s  0.01s bash\n",
            "",
            0,
        )
