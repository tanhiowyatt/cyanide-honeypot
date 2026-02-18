import argparse
import asyncio
import random

from .base import Command


class PingCommand(Command):
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="ping", add_help=False)
        parser.add_argument("-c", "--count", type=int, default=4)
        parser.add_argument("host", nargs="?")

        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1

        host = parsed.host
        if not host:
            if unknown:
                host = unknown[-1]
            else:
                return "", "ping: usage error: Destination address required\n", 2

        count = parsed.count

        # Simulate Unreachable hosts
        # Block common honeypot-detection patterns or just vary it
        unreachable_patterns = ["donotping", "internal.corp", "10.0", "192.168.99"]
        is_reachable = not any(p in host for p in unreachable_patterns)

        if not is_reachable:
            return (
                f"PING {host} ({host}) 56(84) bytes of data.\nFrom 127.0.0.1 icmp_seq=1 Destination Host Unreachable\n",
                "",
                1,
            )

        # Simulate pings
        out = f"PING {host} ({host}) 56(84) bytes of data.\n"
        for i in range(1, count + 1):
            # Realistic latency variations
            latency = random.uniform(5.0, 50.0) if "." in host else random.uniform(0.1, 2.0)
            out += f"64 bytes from {host}: icmp_seq={i} ttl=64 time={latency:.2f} ms\n"
            await asyncio.sleep(0.01)  # Small simulation delay

        out += f"\n--- {host} ping statistics ---\n"
        out += (
            f"{count} packets transmitted, {count} received, 0% packet loss, time {count*1000}ms\n"
        )
        out += "rtt min/avg/max/mdev = 5.123/15.456/50.789/10.123 ms\n"
        return out, "", 0


class EditorCommand(Command):
    async def execute(self, args, input_data=""):
        # vi/nano mock
        # Simply clear screen and tell user it's a fake editor or just exit
        # Real honeypots might allow editing a temp buffer.
        # For now, just print error or clear screen simulation.
        # But this command is synchronous...
        # We can't interact.
        # So we just say "Error: terminal not fully interactive" or similar,
        # or fake it by printing a "saved" message if a filename is given.

        if args:
            filename = args[0]
            # fake save
            return f"Saved {filename}.\n", "", 0
        return "No filename specified.\n", "", 1
