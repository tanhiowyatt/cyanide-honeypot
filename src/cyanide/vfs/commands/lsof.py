import random

from .base import Command


class LsofCommand(Command):
    async def execute(self, args, input_data=""):
        connections = self.get_random_connections()
        output = "COMMAND  PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
        for conn in connections:
            if conn["state"] == "LISTEN":
                output += f"{conn['name']:<8} {conn['pid']:<7} root    3u  IPv4  {random.randint(10000, 20000)}      0t0  TCP *:{conn['local'].split(':')[-1]} (LISTEN)\n"
            else:
                output += f"{conn['name']:<8} {conn['pid']:<7} root    4u  IPv4  {random.randint(20000, 30000)}      0t0  TCP {conn['local']}->{conn['remote']} ({conn['state']})\n"
        return output, "", 0
