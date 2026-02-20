from .base import Command


class DoasCommand(Command):
    async def execute(self, args, input_data=""):
        return await self.auth_and_execute(args, input_data=input_data, paths_to_check=["/root"])
