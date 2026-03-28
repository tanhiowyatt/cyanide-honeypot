import asyncio

from .base import Command


class NcCommand(Command):
    # Function 252: Executes the 'nc' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if "-e" in args:
            return "", "", 0
        return "Usage: nc [options] [hostname] [port]\n", "", 1
