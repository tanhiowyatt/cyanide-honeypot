from .base import Command


class IpCommand(Command):
    async def execute(self, args, input_data=""):
        if not args:
            return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n", "", 0

        obj = args[0]
        if obj in ("addr", "address", "a"):
            mac = self.generate_mac()
            return (
                (
                    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                    "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                    "    inet 127.0.0.1/8 scope host lo\n"
                    "       valid_lft forever preferred_lft forever\n"
                    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n"
                    f"    link/ether {mac} brd ff:ff:ff:ff:ff:ff\n"
                    f"    inet {self.get_ip_addr()}/24 brd 192.168.1.255 scope global eth0\n"
                    "       valid_lft forever preferred_lft forever\n"
                ),
                "",
                0,
            )
        elif obj in ("route", "r"):
            return (
                (
                    "default via 192.168.1.1 dev eth0 proto static\n"
                    f"192.168.1.0/24 dev eth0 proto kernel scope link src {self.get_ip_addr()}\n"
                ),
                "",
                0,
            )

        return f'Object "{obj}" is unknown, try "ip help".\n', "", 1
