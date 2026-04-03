import asyncio
import json
from pathlib import Path
from typing import Any

import asyncssh
import pytest

from cyanide.core.server import CyanideServer


@pytest.fixture
def advanced_config(tmp_path: Path) -> dict[str, Any]:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return {
        "ssh": {"enabled": True, "port": 0, "backend_mode": "emulated", "vfs_persistence": False},
        "telnet": {"enabled": False},
        "metrics": {"enabled": False},
        "logging": {"directory": str(log_dir)},
        "profiles_dir": "configs/profiles",
        "os_profile": "ubuntu",
        "users": [{"user": "root", "pass": "toor"}],
        "max_connections_per_minute": 1000,
        "max_sessions_per_ip": 100,
        "shell": {"max_chain_depth": 50, "max_output_size": 1024}, 
    }

@pytest.mark.asyncio
async def test_log_correlation(advanced_config: dict[str, Any]) -> None:
    """Verify session_id matches across server and fs logs."""
    server = CyanideServer(advanced_config)
    task = asyncio.create_task(server.start())

    await asyncio.sleep(1)
    port = server.ssh_server.sockets[0].getsockname()[1]

    try:
        async with asyncssh.connect(
            "127.0.0.1", port=port, username="root", password="toor", known_hosts=None
        ) as conn:
            await conn.run("ls -la")

        await asyncio.sleep(1)

        log_dir = Path(advanced_config["logging"]["directory"])
        fs_log = log_dir / "cyanide-fs.json"

        with open(fs_log, "r") as f:
            fs_entries = [json.loads(line) for line in f if line.strip()]

        session_ids = [
            e["session"] for e in fs_entries if "session" in e and e["session"] != "system"
        ]
        assert len(session_ids) > 0
        target_session = session_ids[0]

        audit_log = log_dir / "tty" / f"ssh_127.0.0.1_{target_session}" / "audit.json"
        assert audit_log.exists(), f"Audit log {audit_log} not found"

        with open(audit_log, "r") as f:
            audit_entries = [json.loads(line) for line in f if line.strip()]

        found_correlation = any(e["session"] == target_session for e in audit_entries)
        assert found_correlation, f"Session ID {target_session} not found in audit log"

    finally:
        await server.stop()
        task.cancel()


@pytest.mark.asyncio
async def test_session_isolation(advanced_config: dict[str, Any]) -> None:
    """Verify that changes in one session don't affect another."""
    server = CyanideServer(advanced_config)
    task = asyncio.create_task(server.start())
    await asyncio.sleep(1)
    port = server.ssh_server.sockets[0].getsockname()[1]

    try:
        # Session 1: Create a file
        async with asyncssh.connect(
            "127.0.0.1", port=port, username="root", password="toor", known_hosts=None
        ) as conn1:
            await conn1.run("mkdir -p /tmp")
            await conn1.run("echo 'SECRET' > /tmp/isolation_test.txt")
            result = await conn1.run("ls /tmp/isolation_test.txt")
            stdout = str(result.stdout or "")
            assert "isolation_test.txt" in stdout

        # Session 2: Check if file exists
        async with asyncssh.connect(
            "127.0.0.1", port=port, username="root", password="toor", known_hosts=None
        ) as conn2:
            result = await conn2.run("ls /tmp/isolation_test.txt")
            stderr = str(result.stderr or "")
            assert "No such file" in stderr or result.exit_status != 0

    finally:
        await server.stop()
        task.cancel()


@pytest.mark.asyncio
async def test_resource_limits(advanced_config: dict[str, Any]) -> None:
    """Verify protection against massive output or deep command chains."""
    server = CyanideServer(advanced_config)
    task = asyncio.create_task(server.start())
    await asyncio.sleep(1)
    port = server.ssh_server.sockets[0].getsockname()[1]

    try:
        async with asyncssh.connect(
            "127.0.0.1", port=port, username="root", password="toor", known_hosts=None
        ) as conn:
            # 1. Deep chaining test (max_chain_depth is 50 in config)
            deep_cmd = " && ".join(["echo ok"] * 60)
            result = await conn.run(deep_cmd)
            stderr = str(result.stderr or "")
            assert "maximum command chain depth exceeded" in stderr
            assert result.exit_status != 0

            # 2. Output size limit test (max_output_size is 1024 bytes)
            large_output_cmd = " ; ".join(["echo 'THIS_IS_A_LONG_STRING_REPEATED_MANY_TIMES'"] * 50)
            result = await conn.run(large_output_cmd)
            stdout = str(result.stdout or "")
            stderr = str(result.stderr or "")
            assert "[output truncated]" in stdout
            assert "maximum output size exceeded" in stderr
            assert result.exit_status != 0

    finally:
        await server.stop()
        task.cancel()
