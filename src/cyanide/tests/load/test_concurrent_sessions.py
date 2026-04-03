import asyncio
import time

import asyncssh
import pytest
import pytest_asyncio

from cyanide.core.server import CyanideServer


@pytest_asyncio.fixture
async def load_test_server(tmp_path):
    config = {
        "ssh": {"enabled": True, "port": 0, "backend_mode": "emulated"},
        "telnet": {"enabled": False},
        "metrics": {"enabled": False},
        "logging": {"directory": str(tmp_path / "logs")},
        "quarantine_path": str(tmp_path / "quarantine"),
        "users": [{"user": "root", "pass": "admin"}],
        "ml": {"enabled": False},
        "max_sessions": 100,
        "max_sessions_per_ip": 100,
    }
    server = CyanideServer(config)
    task = asyncio.create_task(server.start())

    for _ in range(20):
        if server.ssh_server:
            break
        await asyncio.sleep(0.1)

    yield server
    await server.stop()
    task.cancel()


@pytest.mark.asyncio
async def test_concurrent_sessions_load(load_test_server):
    """Test the honeypot's ability to handle multiple concurrent sessions."""
    port = load_test_server.ssh_server.sockets[0].getsockname()[1]
    target_host = "127.0.0.1"
    concurrency = 20

    async def simulate_session(i):
        start = time.time()
        try:
            async with asyncssh.connect(
                target_host, port=port, username="root", password="admin", known_hosts=None
            ) as conn:
                await conn.run("whoami", timeout=5)
                latency = time.time() - start
                return True, latency
        except Exception as e:
            return False, str(e)

    tasks = [simulate_session(i) for i in range(concurrency)]
    results = await asyncio.gather(*tasks)

    success_count = sum(1 for r in results if r[0])
    latencies = [r[1] for r in results if r[0]]

    print(f"\n[Load Test] Success: {success_count}/{concurrency}")
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        print(f"[Load Test] Avg Latency: {avg_latency:.4f}s")

    assert (
        success_count >= concurrency * 0.9
    ), f"Success rate too low: {success_count}/{concurrency}"
