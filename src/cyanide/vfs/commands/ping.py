import asyncio

from .base import Command


class PingCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if not args:
            return "", "ping: usage error: Destination address required\n", 1

        # Find the first non-flag argument as hostname
        hostname = next((arg for arg in args if not arg.startswith("-")), None)

        # If the last argument is a number (count for -c), the previous one might be hostname
        # or it might be something like ping -c 1 8.8.8.8
        # Let's be simple: last non-flag argument is usually the host
        clean_args = [arg for arg in args if not arg.startswith("-")]
        if not clean_args:
            return "", "ping: usage error: Destination address required\n", 1

        # In ping -c 1 8.8.8.8, args are ['-c', '1', '8.8.8.8']
        # 1 is not a flag but it's a value for -c
        # Standard ping usually has hostname last
        hostname = clean_args[-1]

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
