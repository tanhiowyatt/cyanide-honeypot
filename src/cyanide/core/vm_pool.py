import asyncio
import logging
import secrets
import time

VM_POOL_LOGGER_NAME = "cyanide.vm_pool"
logger = logging.getLogger(VM_POOL_LOGGER_NAME)

try:
    from cyanide.core.libvirt_pool import Lease, LibvirtPool
except ImportError:
    LibvirtPool = None
    Lease = None


class SimplePool:
    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger
        self.targets = []
        self.failed_targets = {}  # (host, port) -> last_failure_time
        self.failure_threshold = 300  # 5 minutes
        pool_conf = config.get("pool", {})
        target_str = pool_conf.get("targets", "")

        if target_str:
            for t in target_str.split(","):
                pass_parts = t.strip().split(":")
                if len(pass_parts) == 2:
                    self.targets.append((pass_parts[0], int(pass_parts[1])))
                elif len(pass_parts) == 1:
                    self.targets.append((pass_parts[0], 22))

        if (
            pool_conf.get("enabled", False)
            and not self.targets
            and pool_conf.get("mode") == "simple"
        ):
            logging.getLogger(VM_POOL_LOGGER_NAME).warning(
                "SimplePool enabled but no targets configured in 'pool.targets'."
            )

    def report_failure(self, host: str, port: int):
        """Mark a target as failed temporarily."""
        logger.warning(f"SimplePool: Reporting failure for {host}:{port}")
        self.failed_targets[(host, port)] = time.time()
        if self.logger:
            self.logger.log_event(
                "system", "pool_failure", {"backend": "simple", "host": host, "port": port}
            )

    async def start(self):
        # No background services to initialize for SimplePool.
        await asyncio.sleep(0)

    async def stop(self):
        # No background tasks to clean up for SimplePool.
        await asyncio.sleep(0)

    async def reserve_target(self, session_id: str, protocol: str):
        await asyncio.sleep(0)
        if not self.targets:
            # We already warned in __init__, so just return None here.
            return None

        now = time.time()
        # Filter out targets that failed recently
        available_targets = [
            t
            for t in self.targets
            if t not in self.failed_targets
            or (now - self.failed_targets[t] > self.failure_threshold)
        ]

        if not available_targets:
            if self.logger:
                self.logger.log_event(
                    "system", "pool_fallback", {"backend": "simple", "reason": "all_targets_failed"}
                )
            available_targets = self.targets

        target = secrets.choice(available_targets)

        if Lease is not None:
            lease = Lease(
                host=target[0],
                port=target[1],
                vm_id="simple",
                protocol=protocol,
                session_id=session_id,
                timestamp=0.0,
            )
            if self.logger:
                self.logger.log_event(
                    session_id,
                    "pool_reserved",
                    {
                        "backend": "simple",
                        "host": target[0],
                        "port": target[1],
                        "protocol": protocol,
                    },
                )
            return lease
        return target

    async def release_target(self, lease):  # ← оставляем, если есть await внутри
        pass


class VMPool:
    """
    Manages a pool of backend VM addresses (e.g., QEMU instances).
    Provides targets for the proxy services.
    """

    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger
        pool_conf = config.get("pool", {})
        pool_enabled = pool_conf.get("enabled", False)
        pool_mode = pool_conf.get("mode", "libvirt")
        self.backend = None

        if pool_enabled and pool_mode == "libvirt":
            if LibvirtPool is not None:
                try:
                    self.backend = LibvirtPool(config, logger=logger)
                except Exception as e:
                    if self.logger:
                        self.logger.log_event(
                            "system", "pool_error", {"backend": "libvirt", "error": str(e)}
                        )
                    logging.getLogger(VM_POOL_LOGGER_NAME).error(
                        f"Failed to load LibvirtPool: {e}. Falling back to SimplePool."
                    )
                    self.backend = SimplePool(config, logger=logger)
            else:
                logging.getLogger(VM_POOL_LOGGER_NAME).error(
                    "Failed to load LibvirtPool: libvirt-python is required for libvirt pool mode. Falling back to SimplePool."
                )
                self.backend = SimplePool(config, logger=logger)
        else:
            self.backend = SimplePool(config, logger=logger)

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

    def report_failure(self, host, port):
        """
        Report a failed backend. Could disable it temporarily.
        """
        assert self.backend is not None
        if hasattr(self.backend, "report_failure"):
            self.backend.report_failure(host, port)
        else:
            logger.debug(
                f"VMPool: Backend {type(self.backend).__name__} does not support report_failure"
            )
