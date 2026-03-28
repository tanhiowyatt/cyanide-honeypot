import asyncio

from .base import Command


class PerlCommand(Command):
    # Function 254: Executes the 'perl' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if "-e" in args:
            return "", "", 0
        if "-v" in args:
            return (
                (
                    "This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi\n"
                ),
                "",
                0,
            )
        return "", "", 0
