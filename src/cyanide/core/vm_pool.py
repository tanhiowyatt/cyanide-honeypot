import random
import logging

logger = logging.getLogger("cyanide.vm_pool")

try:
    from cyanide.core.libvirt_pool import LibvirtPool, Lease
except ImportError:
    LibvirtPool = None
    Lease = None


class SimplePool:
    def __init__(self, config):
        self.targets = []
        pool_conf = config.get("pool", {})
        target_str = pool_conf.get("targets", "")

        if target_str:
            for t in target_str.split(","):
                pass_parts = t.strip().split(":")
                if len(pass_parts) == 2:
                    self.targets.append((pass_parts[0], int(pass_parts[1])))
                elif len(pass_parts) == 1:
                    self.targets.append((pass_parts[0], 22))

    async def start(self):
        pass

    async def stop(self):
        pass

    async def reserve_target(self, session_id: str, protocol: str):
        if not self.targets:
            return None
        target = random.choice(self.targets)
        if Lease is not None:
            return Lease(host=target[0], port=target[1], vm_id="simple", protocol=protocol, session_id=session_id, timestamp=0.0)
        else:
            return target

    async def release_target(self, lease):
        pass


class VMPool:
    """
    Manages a pool of backend VM addresses (e.g., QEMU instances).
    Provides targets for the proxy services.
    """

    def __init__(self, config):
        self.config = config
        pool_conf = config.get("pool", {})
        pool_enabled = pool_conf.get("enabled", False)
        pool_mode = pool_conf.get("mode", "libvirt")
        self.backend = None

        if pool_enabled and pool_mode == "libvirt":
            if LibvirtPool is not None:
                try:
                    self.backend = LibvirtPool(config)
                except Exception as e:
                    logger.error(f"Failed to load LibvirtPool: {e}. Falling back to SimplePool.")
                    self.backend = SimplePool(config)
            else:
                logger.error("Failed to load LibvirtPool: libvirt-python is required for libvirt pool mode. Falling back to SimplePool.")
                self.backend = SimplePool(config)
        else:
            self.backend = SimplePool(config)

    async def start(self):
        assert self.backend is not None
        await self.backend.start()

    async def stop(self):
        assert self.backend is not None
        await self.backend.stop()

    async def reserve_target(self, session_id: str, protocol: str):
        """
        Reserve a VM target. Returns a Lease object (or tuple for SimplePool if imported without dataclass).
        """
        assert self.backend is not None
        return await self.backend.reserve_target(session_id, protocol)

    async def release_target(self, lease):
        """
        Release a leased VM target.
        """
        assert self.backend is not None
        await self.backend.release_target(lease)

    def get_target(self):
        """
        Legacy GET. Not recommended if using libvirt.
        """
        if isinstance(self.backend, SimplePool):
            if not self.backend.targets:
                return None
            return random.choice(self.backend.targets)
        return None

    def report_failure(self, host, port):
        """
        Report a failed backend. Could disable it temporarily.
        """
        pass
