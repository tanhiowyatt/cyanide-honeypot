from .base import Command


class DoasCommand(Command):
    # Function 224: Executes the 'doas' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        return await self.auth_and_execute(args, input_data=input_data, paths_to_check=["/root"])
