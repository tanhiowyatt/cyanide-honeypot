import asyncio

from .base import Command


class GccCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if not args:
            return "", "gcc: fatal error: no input files\ncompilation terminated.\n", 1
        return "", "", 0
