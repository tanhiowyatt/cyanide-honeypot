from typing import Any, Dict, Optional, cast

import aiohttp


class GeoIP:
    """
    Async GeoIP Enrichment using ip-api.com (Free, non-commercial use).
    For production, replace with local MMDB or paid API.
    """

    def __init__(self, cache_size=1000):
        self.base_url = "https://ip-api.com/json"
        self.cache: Dict[str, Any] = {}
        self.cache_size = cache_size

    async def lookup(self, ip: str) -> Optional[dict]:
        """
        Lookup IP details.
        Returns: {
            "country": "United States",
            "city": "Ashburn",
            "isp": "Google LLC",
            ...
        }
        """
        if (
            ip in ("127.0.0.1", "localhost", "::1")
            or ip.startswith("192.168.")
            or ip.startswith("10.")
        ):
            return {
                "country": "Local Network",
                "city": "Internal",
                "isp": "Private IP Space",
                "lat": 0.0,
                "lon": 0.0,
                "org": "Internal",
            }

        if ip in self.cache:
            return cast(Dict[Any, Any], self.cache[ip])

        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/{ip}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "success":
                            result = {
                                "country": data.get("country"),
                                "city": data.get("city"),
                                "isp": data.get("isp"),
                                "lat": data.get("lat"),
                                "lon": data.get("lon"),
                                "org": data.get("org"),
                            }
                            if len(self.cache) < self.cache_size:
                                self.cache[ip] = result
                            return result
        except Exception:
            pass

        return None

    async def lookup_ptr(self, ip: str) -> Optional[str]:
        """Perform Reverse DNS (PTR) lookup for an IP."""
        if ip in ("127.0.0.1", "localhost", "::1"):
            return "localhost"

        try:
            import asyncio

            loop = asyncio.get_event_loop()
            # nosemgrep: python.lang.security.audit.network.socket-getnameinfo
            result = await loop.getnameinfo((ip, 0))
            return result[0]
        except Exception:
            return None
