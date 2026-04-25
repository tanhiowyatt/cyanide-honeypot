import asyncio

from .base import Command


class MakeCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0.5)

        makefile_exists = self.fs.exists(self.emulator.resolve_path("Makefile")) or self.fs.exists(
            self.emulator.resolve_path("makefile")
        )

        if not makefile_exists:
            return (
                "",
                "make: *** No targets specified and no makefile found.  Stop.\n",
                2,
            )

        self._log_event("make_execution", {"args": args})

        # Simulate some build output
        output = "gcc -Wall -O2 -c main.c -o main.o\ngcc -Wall -O2 -c utils.c -o utils.o\ngcc main.o utils.o -o output\n"
        return output, "", 0
