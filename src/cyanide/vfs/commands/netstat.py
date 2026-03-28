import asyncio

from .base import Command


class NetstatCommand(Command):
    # Function 253: Executes the 'netstat' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        connections = self.get_random_connections()
        output = (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State      \n"
        )
        for conn in connections:
            output += f"{conn['proto']:<5}      0      0 {conn['local']:<23} {conn['remote']:<23} {conn['state']:<11}\n"
        return output, "", 0
