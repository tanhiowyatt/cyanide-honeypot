from .base import Command


class GccCommand(Command):
    async def execute(self, args, input_data=""):
        if not args:
            return "", "gcc: fatal error: no input files\ncompilation terminated.\n", 1
        return "", "", 0
