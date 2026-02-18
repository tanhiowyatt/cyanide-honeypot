import aiohttp
from typing import Any, Dict, Optional, cast


class GeoIP:
    """
    Async GeoIP Enrichment using ip-api.com (Free, non-commercial use).
    For production, replace with local MMDB or paid API.
    """

    def __init__(self, cache_size=1000):
        self.base_url = "http://ip-api.com/json"
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
        if ip in ("127.0.0.1", "localhost", "::1"):
            return None

        if ip in self.cache:
            return cast(Dict[Any, Any], self.cache[ip])

        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/{ip}"
                async with session.get(url, timeout=3) as resp:
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
                            # Update Cache
                            if len(self.cache) < self.cache_size:
                                self.cache[ip] = result
                            return result
        except Exception:
            # Silently fail to avoid log spam on network issues
            pass

        return None
