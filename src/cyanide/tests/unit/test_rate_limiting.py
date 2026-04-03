import time

from cyanide.services.session_manager import SessionManager


def test_rate_limiting():
    cfg = {
        "max_sessions": 100,
        "max_sessions_per_ip": 10,
        "rate_limit": {"max_connections_per_minute": 2, "ban_duration": 1},  # short ban for testing
    }
    from unittest.mock import MagicMock

    mgr = SessionManager(cfg, MagicMock())
    ip = "1.2.3.4"
    now = time.time()

    # 1. First connection
    allowed, reason = mgr.can_accept(ip)
    assert allowed
    mgr.register_session(ip)

    # 2. Second connection
    allowed, reason = mgr.can_accept(ip)
    assert allowed
    mgr.register_session(ip)

    # 3. Third connection (Should be banned)
    allowed, reason = mgr.can_accept(ip)
    assert not allowed
    assert "rate_limit_exceeded" in reason

    # 4. Verify Ban
    allowed, reason = mgr.can_accept(ip)
    assert not allowed
    assert "ip_banned" in reason

    # 5. Wait for ban expiry and history clear
    from unittest.mock import patch

    with patch("time.time") as mock_time:
        # Advance time by 61 seconds
        mock_time.return_value = now + 61
        allowed, reason = mgr.can_accept(ip)
        assert allowed


def test_per_ip_limit():
    cfg = {"max_sessions": 100, "max_sessions_per_ip": 1}
    from unittest.mock import MagicMock

    mgr = SessionManager(cfg, MagicMock())
    ip = "5.6.7.8"

    # 1. Allowed
    allowed, reason = mgr.can_accept(ip)
    assert allowed
    session_id = mgr.register_session(ip)

    # 2. Blocked by limit
    allowed, reason = mgr.can_accept(ip)
    assert not allowed
    assert "per_ip_limit_reached" in reason

    # 3. Unregister
    mgr.unregister_session(session_id)
    allowed, reason = mgr.can_accept(ip)
    assert allowed
