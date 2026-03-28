import asyncio

from .base import Command


class PingCommand(Command):
    # Function 255: Executes the 'ping' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if not args:
            return "", "ping: usage error: Destination address required\n", 1

        hostname = args[0]
        is_valid, err, ip = self.validate_url(f"https://{hostname}")
        if not is_valid:
            return "", f"ping: {hostname}: {err}\n", 2

        if not ip:
            return "", f"ping: {hostname}: Name or service not known\n", 2

        return (
            (
                f"PING {hostname} ({ip}) 56(84) bytes of data.\n"
                f"64 bytes from {ip}: icmp_seq=1 ttl=64 time=0.045 ms\n"
                f"64 bytes from {ip}: icmp_seq=2 ttl=64 time=0.052 ms\n"
                f"--- {hostname} ping statistics ---\n"
                f"2 packets transmitted, 2 received, 0% packet loss, time 1002ms\n"
            ),
            "",
            0,
        )
