import asyncio
import time

from .base import Command


class JournalctlCommand(Command):
    # Function 244: Executes the 'journalctl' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        now = time.strftime("%b %d %H:%M:%S")
        return (
            (
                f"{now} server sshd[890]: Server listening on 0.0.0.0 port 22.\n"
                f"{now} server sshd[890]: Server listening on :: port 22.\n"
                f"{now} server systemd[1]: Started OpenBSD Secure Shell server.\n"
            ),
            "",
            0,
        )
