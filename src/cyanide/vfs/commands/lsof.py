import asyncio
import secrets

from .base import Command


class LsofCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        connections = self.get_random_connections()
        output = "COMMAND  PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
        rng = secrets.SystemRandom()
        for conn in connections:
            if conn["state"] == "LISTEN":
                output += f"{conn['name']:<8} {conn['pid']:<7} root    3u  IPv4  {rng.randint(10000, 20000)}      0t0  TCP *:{conn['local'].split(':')[-1]} (LISTEN)\n"
            else:
                output += f"{conn['name']:<8} {conn['pid']:<7} root    4u  IPv4  {rng.randint(20000, 30000)}      0t0  TCP {conn['local']}->{conn['remote']} ({conn['state']})\n"
        return output, "", 0
