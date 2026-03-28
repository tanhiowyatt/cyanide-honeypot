import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock libvirt before importing module
sys.modules["libvirt"] = MagicMock()
from cyanide.core.libvirt_pool import LibvirtPool  # noqa: E402


@pytest.fixture(autouse=True)
def mock_libvirt_available():
    import cyanide.core.libvirt_pool

    with (
        patch.object(cyanide.core.libvirt_pool, "LIBVIRT_AVAILABLE", True),
        patch.object(cyanide.core.libvirt_pool, "libvirt", MagicMock()),
    ):
        yield


@pytest.fixture
def pool():
    config = {"pool": {"libvirt_uri": "test:///default", "max_vms": 2}}
    pool = LibvirtPool(config, logger=MagicMock())
    return pool


@pytest.mark.asyncio
async def test_libvirt_start_stop(pool):
    await pool.start()
    assert len(pool._bg_tasks) == 2
    await pool.stop()
    assert pool.conn is None


def test_sync_vms(pool):
    pool.conn.listDomainsID.return_value = [1]
    dom = MagicMock()
    dom.name.return_value = "ubuntu18.04-1"
    pool.conn.lookupByID.return_value = dom
    pool._sync_vms()
    assert "ubuntu18.04-1" in pool.vms


@pytest.mark.asyncio
async def test_reserve_release(pool):
    # reserve when empty
    lease1 = await pool.reserve_target("sess1", "ssh")
    assert lease1.vm_id == "ubuntu18.04-1"
    assert pool.vms["ubuntu18.04-1"]["state"] == "leased"

    # max vms
    lease2 = await pool.reserve_target("sess2", "ssh")
    assert lease2.vm_id == "ubuntu18.04-2"

    lease3 = await pool.reserve_target("sess3", "ssh")
    assert lease3 is None  # exhausted

    # release
    await pool.release_target(lease1)
    assert "sess1" not in pool.leases
    assert pool.vms["ubuntu18.04-1"]["state"] == "rebuilding"


@pytest.mark.asyncio
async def test_report_failure(pool):
    pool.vms["test-vm"] = {"ip": "1.2.3.4", "state": "leased"}
    pool.report_failure("1.2.3.4", 22)
    assert pool.vms["test-vm"]["state"] == "rebuilding"


@pytest.mark.asyncio
async def test_rebuild_vm(pool):
    pool.vms["test-vm"] = {"state": "rebuilding", "ip": "1.2.3.4", "last_used": 0}
    dom = MagicMock()
    dom.isActive.return_value = True
    pool.conn.lookupByName.return_value = dom

    await pool._rebuild_vm("test-vm")
    assert pool.vms["test-vm"]["state"] == "ready"
    assert dom.destroy.called
    assert dom.create.called


def test_get_domain_ip(pool):
    dom = MagicMock()
    # NAT case
    assert pool._get_domain_ip(dom) == "192.168.1.40"

    # No NAT case
    pool.use_nat = False
    dom.interfaceAddresses.return_value = {
        "eth0": {"hwaddr": "mac", "addrs": [{"addr": "1.1.1.1"}]}
    }
    assert pool._get_domain_ip(dom) == "1.1.1.1"
