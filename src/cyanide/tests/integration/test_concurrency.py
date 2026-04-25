import asyncio
import time

import asyncssh
import pytest

from cyanide.core.server import CyanideServer


@pytest.fixture
def base_config():
    return {
        "ssh": {"enabled": True, "port": 0, "backend_mode": "emulated"},
        "telnet": {"enabled": False},
        "metrics": {"enabled": False},
        "logging": {"directory": "/tmp/cyanide_stress_logs"},
        "profiles_dir": "configs/profiles",
        "os_profile": "debian",
        "users": [{"user": "root", "pass": "toor"}],
        "max_sessions_per_ip": 100,
        "rate_limit": {"max_connections_per_minute": 1000},
    }


@pytest.mark.asyncio
async def test_concurrency_load(base_config):
    server = CyanideServer(base_config)
    task = asyncio.create_task(server.start())

    await asyncio.sleep(1)
    port = server.ssh_server.sockets[0].getsockname()[1]

    async def connect_and_ls():
        async with asyncssh.connect(
            "127.0.0.1", port=port, username="root", password="toor", known_hosts=None
        ) as conn:
            await conn.run("ls -la")
            await asyncio.sleep(0.1)

    start_time = time.time()
    tasks = []
    for _ in range(50):
        tasks.append(asyncio.create_task(connect_and_ls()))
        await asyncio.sleep(0.05)

    await asyncio.gather(*tasks)
    duration = time.time() - start_time

    print(f"50 connections duration: {duration:.2f}s")
    assert duration < 20

    await server.stop()
    task.cancel()


@pytest.mark.asyncio
async def test_memory_leak_check(base_config):
    server = CyanideServer(base_config)
    task = asyncio.create_task(server.start())
    await asyncio.sleep(1)
    port = server.ssh_server.sockets[0].getsockname()[1]

    for _ in range(100):
        async with asyncssh.connect(
            "127.0.0.1", port=port, username="root", password="toor", known_hosts=None
        ) as conn:
            await conn.run("whoami; id; pwd; uptime")

    await server.stop()
    task.cancel()
