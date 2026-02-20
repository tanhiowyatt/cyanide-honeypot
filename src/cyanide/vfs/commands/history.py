from .base import Command


class HistoryCommand(Command):
    async def execute(self, args, input_data=""):
        output = ""
        for i, cmd in enumerate(self.emulator.history, 1):
            output += f"{i:>5}  {cmd}\n"
        return output, "", 0
