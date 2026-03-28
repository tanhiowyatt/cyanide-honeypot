from unittest.mock import MagicMock

import pytest

from cyanide.core.server import CyanideServer, SSHServerFactory, SSHSession


@pytest.fixture
def mock_honeypot(mock_logger):
    hp = MagicMock(spec=CyanideServer)
    hp.config = MagicMock()
    hp.stats = MagicMock()
    hp.logger = mock_logger
    return hp


@pytest.fixture
def session(mock_honeypot):
    fs = MagicMock()
    s = SSHSession(mock_honeypot, fs, "1.2.3.4", 1234, "conn1")
    return s


def test_extract_algorithm_name(mock_honeypot):
    factory = SSHServerFactory(mock_honeypot)
    # None case
    assert factory._extract_algorithm_name(None) is None

    # Bytes case
    obj = MagicMock()
    obj.algorithm = b"curve25519-sha256"
    assert factory._extract_algorithm_name(obj) == "curve25519-sha256"


def test_get_ssh_info_fallbacks(session):
    conn = MagicMock()

    # get_extra_info success
    conn.get_extra_info.return_value = "extra_val"
    assert session._get_ssh_info(conn, "test_key") == "extra_val"

    # Internal attribute fallback
    conn.get_extra_info.return_value = None
    conn._internal = b"internal_val"
    assert session._get_ssh_info(conn, "test_key", "_internal", decode=True) == "internal_val"


def test_log_ssh_details(session):
    conn = MagicMock()
    conn.get_extra_info.side_effect = lambda k: {
        "kex": "kex_val",
        "server_host_key": "key_val",
        "cipher": "cipher_val",
        "mac": "mac_val",
        "compression": "comp_val",
    }.get(k)

    session._log_ssh_details(conn)
    assert session.honeypot.logger.log_event.call_count >= 2


def test_fs_audit_hook_priority(mock_honeypot):
    # Manually attach the real method to the mock to test its logic without triggering __init__
    mock_honeypot.config.honeytokens = ["/global/secret"]
    mock_honeypot._fs_audit_hook = CyanideServer._fs_audit_hook.__get__(
        mock_honeypot, CyanideServer
    )

    # Should use global config if present
    mock_honeypot._fs_audit_hook("open", "/global/secret", session_id="s1")
    mock_honeypot.stats.on_honeytoken.assert_called_with("/global/secret")

    # Reset and test profile priority
    mock_honeypot.config.honeytokens = []
    mock_fs = MagicMock()
    mock_fs.honeytokens = ["/profile/secret"]

    mock_honeypot._fs_audit_hook("open", "/profile/secret", fs=mock_fs, session_id="s1")
    mock_honeypot.stats.on_honeytoken.assert_called_with("/profile/secret")
