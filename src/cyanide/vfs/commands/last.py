import asyncio
import time

from .base import Command


class LastCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        now = time.strftime("%a %b %d %H:%M")
        return (
            (
                f"root     pts/0        192.168.1.50     {now}   still logged in\n"
                f"admin    pts/1        10.0.0.2         {now}   still logged in\n"
                f"reboot   system boot  5.4.0-42-generic {now}   running\n"
                f"\nwtmp begins {now}\n"
            ),
            "",
            0,
        )
