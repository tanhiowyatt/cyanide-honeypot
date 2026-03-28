import asyncio

from .base import Command


class RouteCommand(Command):
    # Function 263: Executes the 'route' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if "-n" in args:
            return (
                (
                    "Kernel IP routing table\n"
                    "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
                    "0.0.0.0         192.168.1.1     0.0.0.0         UG    0      0        0 eth0\n"
                    "192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0\n"
                ),
                "",
                0,
            )
        return (
            (
                "Kernel IP routing table\n"
                "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
                "default         gateway         0.0.0.0         UG    0      0        0 eth0\n"
                "192.168.1.0     0.0.0.0         255.255.255.0   U     0      0        0 eth0\n"
            ),
            "",
            0,
        )
