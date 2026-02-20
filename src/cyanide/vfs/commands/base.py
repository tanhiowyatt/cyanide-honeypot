import ipaddress
import socket
import time
from typing import Optional
from urllib.parse import urlparse


class Command:
    """Base class for shell commands."""

    def __init__(self, emulator):
        self.emulator = emulator
        self.fs = emulator.fs
        self.username = emulator.username

    async def auth_and_execute(
        self, args: list[str], input_data: str = "", paths_to_check: Optional[list[str]] = None
    ) -> tuple[str, str, int]:
        """Check for root access and prompt for password if needed, otherwise execute."""
        if self.emulator.username == "root":
            return await self.execute(args, input_data=input_data)

        # Check if any path being accessed is protected
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
            self.emulator.pending_input_prompt = f"[cyanide] password for {self.emulator.username}: "
            return f"[cyanide] password for {self.emulator.username}: ", "", 0

        return await self.execute(args, input_data=input_data)

    async def _on_password_auth(
        self, password: str, args: list[str], input_data: str
    ) -> tuple[str, str, int]:
        # Switch to root on any password for now (honeypot logic)
        self.emulator.username = "root"
        # Optional: update CWD to /root if it was ~ for old user
        return await self.execute(args, input_data=input_data)

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

            # Check DNS cache
            now = time.time()
            if hasattr(self.emulator, "dns_cache") and hostname in self.emulator.dns_cache:
                ip_str, expiry = self.emulator.dns_cache[hostname]
                if now < expiry:
                    if hasattr(self.emulator, "stats"):
                        self.emulator.stats.dns_cache_hits += 1
                    return True, "", ip_str

            if hasattr(self.emulator, "stats"):
                self.emulator.stats.dns_cache_misses += 1

            # Resolve to IP
            try:
                ip_list = socket.getaddrinfo(hostname, None)

                # Check ALL IPs
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
