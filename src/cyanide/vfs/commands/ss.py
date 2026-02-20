from .base import Command


class SsCommand(Command):
    async def execute(self, args, input_data=""):
        connections = self.get_random_connections()
        output = (
            "Netid  State      Recv-Q Send-Q Local Address:Port               Peer Address:Port\n"
        )
        for conn in connections:
            output += f"{conn['proto']:<5}  {conn['state']:<10} 0      128    {conn['local']:<30} {conn['remote']:<30}\n"
        return output, "", 0
