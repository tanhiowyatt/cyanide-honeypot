from .base import Command


class PkexecCommand(Command):
    # Function 256: Executes the 'pkexec' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        if self.emulator.username == "root":
            return "", "", 0

        return await self.auth_and_execute(args, input_data=input_data, paths_to_check=["/root"])
