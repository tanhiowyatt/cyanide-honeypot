import asyncio

from .base import Command


class HistoryCommand(Command):
    # Function 240: Executes the 'history' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        output = ""
        for i, cmd in enumerate(self.emulator.history, 1):
            output += f"{i:>5}  {cmd}\n"
        return output, "", 0
