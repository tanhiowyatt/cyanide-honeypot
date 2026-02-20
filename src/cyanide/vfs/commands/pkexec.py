from .base import Command


class PkexecCommand(Command):
    async def execute(self, args, input_data=""):
        if self.emulator.username == "root":
            return "", "", 0

        # Trigger auth via emulator's pending_input if not handled by auth_and_execute
        return await self.auth_and_execute(args, input_data=input_data, paths_to_check=["/root"])
