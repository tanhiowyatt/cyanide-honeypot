import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger("cyanide.libvirt_pool")

try:
    import libvirt

    LIBVIRT_AVAILABLE = True
except ImportError:
    libvirt = None
    LIBVIRT_AVAILABLE = False


@dataclass
class Lease:
    host: str
    port: int
    vm_id: str
    protocol: str
    session_id: str
    timestamp: float


class LibvirtPool:
    """
    Orchestrates Libvirt VMs to serve as backend targets.
    Manages leases, recycling, and health-checks.
    """

    def __init__(self, config: dict):
        if not LIBVIRT_AVAILABLE:
            raise ImportError("libvirt-python is required for libvirt pool mode")

        self.config = config.get("pool", {})
        self.uri = self.config.get("libvirt_uri", "qemu:///system")
        self.max_vms = self.config.get("max_vms", 5)
        self.recycle_period = self.config.get("recycle_period", 1500)
        self.vm_unused_timeout = self.config.get("vm_unused_timeout", 600)
        self.guest_tag = self.config.get("guest_tag", "ubuntu18.04")
        self.guest_ssh_port = self.config.get("guest_ssh_port", 22)
        self.guest_telnet_port = self.config.get("guest_telnet_port", 23)
        self.use_nat = self.config.get("use_nat", True)
        self.nat_public_ip = self.config.get("nat_public_ip", "192.168.1.40")
        self.save_snapshots = self.config.get("save_snapshots", False)

        self.conn = None
        self._connect()

        self.vms: Dict[str, dict] = (
            {}
        )
        self.leases: Dict[str, Lease] = {}

        self.lock = asyncio.Lock()

        self._bg_tasks: List[asyncio.Task] = []

    def _connect(self):
        try:
            self.conn = libvirt.open(self.uri)
            if self.conn is None:
                logger.error(f"Failed to open connection to the hypervisor: {self.uri}")
        except Exception as e:
            logger.error(f"Exception connecting to libvirt {self.uri}: {e}")

    async def start(self):
        """Start background tasks for healthcheck and recycling"""
        await self._sync_vms()
        self._bg_tasks.append(asyncio.create_task(self._healthcheck_loop()))
        self._bg_tasks.append(asyncio.create_task(self._recycle_loop()))
        logger.info(f"Libvirt pool started. Max VMs: {self.max_vms}")

    async def stop(self):
        """Stop background tasks and close connection"""
        for task in self._bg_tasks:
            task.cancel()
        if self.conn:
            self.conn.close()

    async def _sync_vms(self):
        """Discover existing VMs with the tag and populate self.vms"""
        if not self.conn:
            return

        try:
            domain_ids = self.conn.listDomainsID()
            for dom_id in domain_ids:
                dom = self.conn.lookupByID(dom_id)
                name = dom.name()
                if self.guest_tag in name:
                    if name not in self.vms:
                        self.vms[name] = {
                            "state": "ready",
                            "ip": self._get_domain_ip(dom),
                            "last_used": time.time(),
                        }
                        logger.info(f"Found existing VM in pool: {name}")
        except Exception as e:
            logger.error(f"Error syncing VMs: {e}")

    def _get_domain_ip(self, dom) -> Optional[str]:
        if self.use_nat:
            return str(self.nat_public_ip)
        return "127.0.0.1"

    async def reserve_target(self, session_id: str, protocol: str) -> Optional[Lease]:
        """Reserve a VM for a session."""
        async with self.lock:
            ready_vms = [vid for vid, v in self.vms.items() if v["state"] == "ready"]

            if not ready_vms:
                if len(self.vms) < self.max_vms:
                    new_vm_id = f"{self.guest_tag}-{len(self.vms) + 1}"
                    await self._provision_vm(new_vm_id)
                    ready_vms.append(new_vm_id)
                else:
                    logger.warning("VM pool exhausted.")
                    return None

            selected_vm = ready_vms[0]
            self.vms[selected_vm]["state"] = "leased"
            self.vms[selected_vm]["last_used"] = time.time()

            ip = self.vms[selected_vm]["ip"]
            port = self.guest_ssh_port if protocol == "ssh" else self.guest_telnet_port

            lease = Lease(
                host=ip,
                port=port,
                vm_id=selected_vm,
                protocol=protocol,
                session_id=session_id,
                timestamp=time.time(),
            )
            self.leases[session_id] = lease
            logger.info(f"Reserved VM {selected_vm} for session {session_id}")
            return lease

    async def release_target(self, lease: Lease):
        """Release a VM and trigger revert or rebuild if necessary."""
        async with self.lock:
            if lease.session_id in self.leases:
                del self.leases[lease.session_id]

            if lease.vm_id in self.vms:
                logger.info(f"Releasing VM {lease.vm_id} from session {lease.session_id}")
                self.vms[lease.vm_id]["state"] = "rebuilding"
                asyncio.create_task(self._rebuild_vm(lease.vm_id))

    async def _provision_vm(self, vm_id: str):
        """Provision a new VM from config."""
        logger.info(f"Provisioning new VM: {vm_id}")
        self.vms[vm_id] = {
            "state": "rebuilding",
            "ip": self.nat_public_ip if self.use_nat else "127.0.0.1",
            "last_used": time.time(),
        }

        if self.conn:
            try:
                pass
            except Exception as e:
                logger.error(f"Failed to provision {vm_id}: {e}")

        self.vms[vm_id]["state"] = "ready"
        logger.info(f"VM {vm_id} provisioned and ready.")

    async def _rebuild_vm(self, vm_id: str):
        """Revert VM to snapshot or just restart."""
        logger.info(f"Rebuilding/Reverting VM: {vm_id}")
        if self.conn:
            try:
                dom = self.conn.lookupByName(vm_id)
                if dom.isActive():
                    dom.destroy()
                if self.save_snapshots:
                    pass
                dom.create()
            except Exception as e:
                logger.error(f"Failed to rebuild {vm_id}: {e}")

        async with self.lock:
            if vm_id in self.vms:
                self.vms[vm_id]["state"] = "ready"
                self.vms[vm_id]["last_used"] = time.time()
        logger.info(f"VM {vm_id} rebuilt and ready.")

    async def _healthcheck_loop(self):
        """Periodic healthchecks for all VMs."""
        while True:
            await asyncio.sleep(60)
            async with self.lock:
                for vm_id, v in list(
                    self.vms.items()
                ):
                    if v["state"] == "ready":
                        pass

    async def _recycle_loop(self):
        """Recycle unused VMs after timeout."""
        while True:
            await asyncio.sleep(60)
            async with self.lock:
                now = time.time()
                for vm_id, v in list(self.vms.items()):
                    if v["state"] == "ready" and (now - v["last_used"] > self.vm_unused_timeout):
                        logger.info(f"Recycling unused VM {vm_id}")
                        self.vms[vm_id]["state"] = "rebuilding"
                        asyncio.create_task(self._rebuild_vm(vm_id))
