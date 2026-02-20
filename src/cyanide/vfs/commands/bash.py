from typing import cast

from .base import Command


class BashCommand(Command):
    """Bourne-Again SHell."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        if "-c" in args:
            cmd_index = args.index("-c") + 1
            if cmd_index < len(args):
                # Execute the command string via the same emulator
                result = await self.emulator.execute(args[cmd_index])
                return cast(tuple[str, str, int], result)
            return "", "", 0

        # Interactive shell mock - doesn't actually change much since we're in a honey shell
        if "-i" in args or not args:
            return f"bash: welcome to {self.emulator.username}'s shell\n", "", 0

        return "", "", 0
