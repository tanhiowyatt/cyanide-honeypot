import asyncio

from .base import Command


class GccCommand(Command):
    # Function 235: Executes the 'gcc' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if not args:
            return "", "gcc: fatal error: no input files\ncompilation terminated.\n", 1
        return "", "", 0
