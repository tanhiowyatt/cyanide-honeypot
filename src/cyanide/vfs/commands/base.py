import ipaddress
import random
import socket
import time
from typing import Optional
from urllib.parse import urlparse


class Command:
    """Base class for shell commands."""

    # Function 206: Initializes the class instance and its attributes.
    def __init__(self, emulator):
        self.emulator = emulator
        self.fs = emulator.fs
        self.username = emulator.username

    # Function 207: Retrieves ip addr data.
    def get_ip_addr(self) -> str:
        """Get the simulated IP address of the honeypot."""
        return str(self.emulator.config.get("ip_address", "192.168.1.15"))

    # Function 208: Performs operations related to generate mac.
    def generate_mac(self) -> str:
        """Generate a deterministic-ish MAC address for this session."""
        vendor = [0x08, 0x00, 0x27]
        random.seed(self.emulator.username)
        rest = [random.randint(0x00, 0xFF) for _ in range(3)]
        random.seed(None)
        return ":".join(f"{x:02x}" for x in vendor + rest)

    # Function 209: Retrieves random network stats data.
    def get_random_network_stats(self) -> dict:
        """Generate some random traffic stats."""
        return {
            "rx_packets": random.randint(1000, 50000),
            "rx_bytes": random.randint(100000, 5000000),
            "tx_packets": random.randint(1000, 50000),
            "tx_bytes": random.randint(100000, 5000000),
        }

    # Function 210: Retrieves random connections data.
    def get_random_connections(self, count: int = 3) -> list[dict]:
        """Generate some random active connections."""
        connections = []
        connections.append(
            {
                "proto": "tcp",
                "local": "0.0.0.0:22",
                "remote": "0.0.0.0:*",
                "state": "LISTEN",
                "pid": 890,
                "name": "sshd",
            }
        )
        connections.append(
            {
                "proto": "tcp",
                "local": "0.0.0.0:80",
                "remote": "0.0.0.0:*",
                "state": "LISTEN",
                "pid": 1024,
                "name": "apache2",
            }
        )

        states = ["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"]
        for _ in range(count):
            remote_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            remote_port = random.randint(1024, 65535)
            local_port = random.choice(
                [22, 80] if random.random() > 0.5 else [random.randint(30000, 60000)]
            )
            connections.append(
                {
                    "proto": "tcp",
                    "local": f"192.168.1.15:{local_port}",
                    "remote": f"{remote_ip}:{remote_port}",
                    "state": random.choice(states),
                    "pid": random.randint(1000, 5000),
                    "name": random.choice(["sshd", "apache2", "curl", "wget", "bash"]),
                }
            )
        return connections

    # Function 211: Executes the 'base' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the command logic. Must be implemented by subclasses."""
        raise NotImplementedError

    # Function 212: Performs operations related to auth and execute.
    async def auth_and_execute(
        self, args: list[str], input_data: str = "", paths_to_check: Optional[list[str]] = None
    ) -> tuple[str, str, int]:
        """Check for root access and prompt for password if needed, otherwise execute."""
        if self.emulator.username == "root":
            return await self.execute(args, input_data=input_data)

        check_paths = paths_to_check or args
        needs_root = False
        for p in check_paths:
            if not isinstance(p, str):
                continue
            abs_p = self.emulator.resolve_path(p)
            if abs_p == "/root" or abs_p.startswith("/root/"):
                needs_root = True
                break

        if needs_root:
            self.emulator.pending_input_callback = lambda pwd: self._on_password_auth(
                pwd, args, input_data
            )
            self.emulator.pending_input_prompt = (
                f"[cyanide] password for {self.emulator.username}: "
            )
            return f"[cyanide] password for {self.emulator.username}: ", "", 0

        return await self.execute(args, input_data=input_data)

    # Function 213: Performs operations related to on password auth.
    async def _on_password_auth(
        self, password: str, args: list[str], input_data: str
    ) -> tuple[str, str, int]:
        self.emulator.username = "root"
        return await self.execute(args, input_data=input_data)

    # Function 214: Performs operations related to validate url.
    def validate_url(self, url: str) -> tuple[bool, str, Optional[str]]:
        """Validate URL to prevent SSRF and local file access.

        Returns:
            (is_valid, error_message, resolved_ip)
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False, f"Protocol '{parsed.scheme}' not supported or disabled.", None

            hostname = parsed.hostname
            if not hostname:
                return False, "Invalid URL", None

            now = time.time()
            if hasattr(self.emulator, "dns_cache") and hostname in self.emulator.dns_cache:
                ip_str, expiry = self.emulator.dns_cache[hostname]
                if now < expiry:
                    if hasattr(self.emulator, "stats"):
                        self.emulator.stats.dns_cache_hits += 1
                    return True, "", ip_str

            if hasattr(self.emulator, "stats"):
                self.emulator.stats.dns_cache_misses += 1

            try:
                ip_list = socket.getaddrinfo(hostname, None)

                allow_local = (
                    self.emulator.config.get("allow_local_network", False)
                    if hasattr(self.emulator, "config")
                    else False
                )

                valid_ip = None
                for item in ip_list:
                    ip_str = item[4][0]
                    ip_obj = ipaddress.ip_address(ip_str)

                    if not allow_local and (
                        ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                    ):
                        return (
                            False,
                            f"Access to private/local resource '{hostname}' ({ip_str}) denied.",
                            None,
                        )

                    if not valid_ip:
                        valid_ip = ip_str

                if hasattr(self.emulator, "dns_cache") and valid_ip:
                    ttl = (
                        self.emulator.config.get("dns_cache_ttl", 60)
                        if hasattr(self.emulator, "config")
                        else 60
                    )
                    self.emulator.dns_cache[hostname] = (str(valid_ip), now + ttl)

                return True, "", str(valid_ip) if valid_ip else None

            except socket.gaierror:
                return False, f"Could not resolve host: {hostname}", None

        except ValueError:
            return False, "Invalid URL format", None
        except Exception as e:
            return False, f"URL validation error: {e}", None
