import asyncio

from .base import Command


class MakeCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        return "make: *** No targets specified and no makefile found.  Stop.\n", "", 2
