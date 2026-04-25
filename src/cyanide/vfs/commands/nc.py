import asyncio

from .base import Command


class NcCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0.5)

        self._log_event("nc_execution", {"args": args})

        if "--help" in args or "-h" in args:
            return "Usage: nc [options] [hostname] [port]\n", "", 0

        # Handle nc -e /bin/sh
        if "-e" in args:
            try:
                e_idx = args.index("-e")
                if e_idx + 1 < len(args):
                    shell = args[e_idx + 1]
                    self._log_event(
                        "nc_reverse_shell_attempt",
                        {"shell": shell},
                    )
                    # Simulate waiting for connection
                    await asyncio.sleep(2)
                    return "", "nc: connection timed out\n", 1
            except Exception:
                pass

        # Parse host and port
        host_port = [a for a in args if not a.startswith("-")]
        if len(host_port) >= 2:
            await asyncio.sleep(1)
            return (
                "",
                f"nc: connect to {host_port[0]} port {host_port[1]} (tcp) failed: Connection refused\n",
                1,
            )

        return "Usage: nc [options] [hostname] [port]\n", "", 1
