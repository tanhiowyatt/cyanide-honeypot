import asyncio

from .base import Command


class IfconfigCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        mac = self.generate_mac()
        stats = self.get_random_network_stats()
        return (
            (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                f"        inet {self.get_ip_addr()}  netmask 255.255.255.0  broadcast 192.168.1.255\n"
                f"        ether {mac}  txqueuelen 1000  (Ethernet)\n"
                f"        RX packets {stats['rx_packets']}  bytes {stats['rx_bytes']} ({stats['rx_bytes']//1024} KiB)\n"
                "        RX errors 0  dropped 0  overruns 0  frame 0\n"
                f"        TX packets {stats['tx_packets']}  bytes {stats['tx_bytes']} ({stats['tx_bytes']//1024} KiB)\n"
                "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                "        inet 127.0.0.1  netmask 255.0.0.0\n"
                "        loop  txqueuelen 1000  (Local Loopback)\n"
                "        RX packets 88  bytes 6210 (6.0 KiB)\n"
                "        RX errors 0  dropped 0  overruns 0  frame 0\n"
                "        TX packets 88  bytes 6210 (6.0 KiB)\n"
                "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n"
            ),
            "",
            0,
        )
