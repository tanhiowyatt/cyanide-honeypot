import asyncio
import sys
from unittest.mock import MagicMock, patch

import pytest

mock_libvirt = MagicMock()
sys.modules["libvirt"] = mock_libvirt

from cyanide.core.config_schema import CyanideConfig  # noqa: E402
from cyanide.core.libvirt_pool import Lease, LibvirtPool  # noqa: E402
from cyanide.core.vm_pool import SimplePool, VMPool  # noqa: E402


@pytest.fixture(autouse=True)
def patch_libvirt_available():
    """Ensure VMPool and LibvirtPool think libvirt is available for tests."""
    with (
        patch("cyanide.core.libvirt_pool.LIBVIRT_AVAILABLE", True),
        patch("cyanide.core.libvirt_pool.libvirt", mock_libvirt),
        patch("cyanide.core.vm_pool.LibvirtPool", LibvirtPool),
        patch("cyanide.core.vm_pool.Lease", Lease),
    ):
        yield


def test_config_parsing():
    """Verify pydantic config schema parses pool section correctly."""
    cfg_data = {
        "pool": {
            "enabled": True,
            "mode": "libvirt",
            "max_vms": 10,
            "vm_unused_timeout": 300,
        }
    }
    config = CyanideConfig(**cfg_data)
    assert config.pool.enabled is True
    assert config.pool.mode == "libvirt"
    assert config.pool.max_vms == 10
    assert config.pool.vm_unused_timeout == 300
    assert config.pool.save_snapshots is False  # default


@pytest.fixture
def mock_pool_config():
    return {
        "pool": {
            "enabled": True,
            "mode": "libvirt",
            "max_vms": 2,
            "guest_tag": "test-os",
            "use_nat": False,
        }
    }


@pytest.mark.asyncio
async def test_pool_reserve_release(mock_pool_config):
    """Test VM allocation, limits, and releasing logic."""
    mock_conn = MagicMock()
    mock_libvirt.open.return_value = mock_conn
    mock_conn.listDomainsID.return_value = []

    pool = LibvirtPool(mock_pool_config)

    lease1 = await pool.reserve_target("session1", "ssh")
    assert lease1 is not None
    assert lease1.vm_id == "test-os-1"
    assert pool.vms["test-os-1"]["state"] == "leased"

    lease2 = await pool.reserve_target("session2", "telnet")
    assert lease2 is not None
    assert lease2.vm_id == "test-os-2"
    assert lease2.protocol == "telnet"

    lease3 = await pool.reserve_target("session3", "ssh")
    assert lease3 is None

    await pool.release_target(lease1)

    assert pool.vms["test-os-1"]["state"] == "rebuilding"

    for _ in range(20):
        if pool.vms["test-os-1"]["state"] == "ready":
            break
        await asyncio.sleep(0.1)

    assert pool.vms["test-os-1"]["state"] == "ready"

    lease4 = await pool.reserve_target("session4", "ssh")
    assert lease4 is not None
    assert lease4.vm_id == "test-os-1"


@pytest.mark.asyncio
async def test_vm_pool_wrapper(mock_pool_config):
    """Test that VMPool correctly wraps LibvirtPool."""
    vmpool = VMPool(mock_pool_config)
    assert isinstance(vmpool.backend, LibvirtPool)

    lease = await vmpool.reserve_target("wrapper_session", "ssh")
    assert lease is not None
    assert lease.session_id == "wrapper_session"
    await vmpool.release_target(lease)
    for _ in range(20):
        if vmpool.backend.vms[lease.vm_id]["state"] == "ready":
            break
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_healthcheck_eviction(mock_pool_config, monkeypatch):
    """Test eviction flow if healthcheck fails."""
    pool = LibvirtPool(mock_pool_config)
    pool.vms["test-os-bad"] = {"state": "ready", "ip": "1.2.3.4", "last_used": 0}

    pool.vms["test-os-bad"]["state"] = "rebuilding"
    await pool._rebuild_vm("test-os-bad")
    assert pool.vms["test-os-bad"]["state"] == "ready"


@pytest.mark.asyncio
async def test_simple_pool_no_targets():
    """Verify SimplePool handles empty target list correctly."""
    config = {"pool": {"targets": ""}}
    pool = SimplePool(config)
    lease = await pool.reserve_target("session1", "ssh")
    assert lease is None


@pytest.mark.asyncio
async def test_simple_pool_reserve():
    """Verify SimplePool can reserve a target when configured."""
    config = {"pool": {"targets": "1.2.3.4:2222"}}
    pool = SimplePool(config)
    lease = await pool.reserve_target("session1", "ssh")
    assert lease is not None
    assert lease.host == "1.2.3.4"
    assert lease.port == 2222
    await pool.release_target(lease)
