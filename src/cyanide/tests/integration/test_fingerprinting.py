import asyncio
from pathlib import Path

import asyncssh
import pytest

from cyanide.core.server import CyanideServer


@pytest.fixture
def base_config(tmp_path):
    return {
        "ssh": {"enabled": True, "port": 0, "backend_mode": "emulated"},
        "telnet": {"enabled": False},
        "metrics": {"enabled": False},
        "logging": {"directory": str(tmp_path / "logs")},
        "quarantine_path": str(tmp_path / "quarantine"),
        "profiles_dir": "configs/profiles",
        "users": [{"user": "admin", "pass": "admin"}],
    }


async def get_ssh_banner_and_handshake(host, port):
    try:
        async with asyncssh.connect(
            host, port, username="admin", password="password", known_hosts=None, login_timeout=2
        ) as conn:
            banner = conn.get_extra_info("server_version")
            return banner
    except Exception as e:
        if "Authentication failed" in str(e) or "Permission denied" in str(e):
            pass
        return None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "os_type, expected_banner",
    [
        ("ubuntu", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"),
        ("debian", "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"),
        ("centos", "SSH-2.0-OpenSSH_7.4"),
    ],
)
async def test_ssh_fingerprint(base_config, os_type, expected_banner):
    config = base_config.copy()
    config["os_profile"] = os_type

    server = CyanideServer(config)
    server.config["profiles_dir"] = "configs/profiles"

    task = asyncio.create_task(server.start())

    port = None
    for _ in range(20):
        if server.ssh_server and server.ssh_server.sockets:
            port = server.ssh_server.sockets[0].getsockname()[1]
            break
        await asyncio.sleep(0.2)

    if port is None:
        await server.stop()
        pytest.fail("Server failed to start and bind to a port")

    try:
        banner = await get_ssh_banner_and_handshake("127.0.0.1", port)
        if banner:
            assert banner == expected_banner
        await asyncio.sleep(1.0)

        log_dir = Path(base_config["logging"]["directory"])
        fs_log = log_dir / "cyanide-fs.json"
        assert fs_log.exists()

        import json

        with open(fs_log, "r") as f:
            lines = f.readlines()
            assert len(lines) >= 3

            open_evt = json.loads(lines[0])
            assert open_evt["eventid"] == "ssh.connect"
            assert "src_ip" in open_evt
            assert "geoip" in open_evt
            assert open_evt["geoip"]["country"] == "Local Network"

            fp_evt = json.loads(lines[1])
            assert fp_evt["eventid"] in ("client_fingerprint", "ssh_negotiated")
            assert "src_ip" in fp_evt
            assert "geoip" in fp_evt

            session_id = open_evt["session"]
            src_ip = open_evt["src_ip"]
            audit_path = log_dir / "tty" / f"ssh_{src_ip}_{session_id}" / "audit.json"
            assert audit_path.exists()
            with open(audit_path, "r") as af:
                audit_lines = af.readlines()
                for i in range(min(len(lines), len(audit_lines))):
                    assert lines[i] == audit_lines[i]

    finally:
        await server.stop()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
