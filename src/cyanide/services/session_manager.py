import time
import uuid
from typing import Dict, List


class SessionManager:
    """
    Manages active session counts and enforces connection limits.
    """

    def __init__(self, config: Dict):
        self.max_sessions = config.get("max_sessions", 100)
        self.max_sessions_per_ip = config.get("max_sessions_per_ip", 5)
        self.session_timeout = config.get("session_timeout", 300)

        self.session_timeout = config.get("session_timeout", 300)

        # Rate Limiting
        self.max_connections_per_minute = config.get("rate_limit", {}).get(
            "max_connections_per_minute", 60
        )
        self.ban_duration = config.get("rate_limit", {}).get("ban_duration", 3600)

        self.active_sessions = 0
        self.sessions_per_ip = {}  # Map of IP -> count

        self.banned_ips: Dict[str, float] = {}  # IP -> expiry_timestamp
        self.connection_history: Dict[str, List[float]] = {}  # IP -> list of timestamps

    def can_accept(self, ip: str) -> tuple[bool, str]:
        """
        Check if a connection from IP can be accepted.
        Returns: (accepted, rejection_reason)
        """
        # 1. Check Ban Status
        now = time.time()
        if ip in self.banned_ips:
            if now < self.banned_ips[ip]:
                return False, "ip_banned"
            else:
                del self.banned_ips[ip]  # Ban expired

        # 2. Rate Limiting (Token Bucket / Sliding Window)
        history = self.connection_history.get(ip, [])
        # Remove old entries
        history = [t for t in history if now - t < 60]
        self.connection_history[ip] = history

        if len(history) >= self.max_connections_per_minute:
            self.banned_ips[ip] = now + self.ban_duration
            return False, "rate_limit_exceeded (banned)"

        # Record attempt (optimistic)
        self.connection_history[ip].append(now)

        # 3. Concurrency Limits
        if self.active_sessions >= self.max_sessions:
            return False, "global_limit_reached"

        per_ip_count = self.sessions_per_ip.get(ip, 0)
        if per_ip_count >= self.max_sessions_per_ip:
            return False, "per_ip_limit_reached"

        return True, ""

    def register_session(self, ip: str, protocol: str = "unknown") -> str:
        """
        Register a new session.
        Returns: session_id
        """
        self.active_sessions += 1
        self.sessions_per_ip[ip] = self.sessions_per_ip.get(ip, 0) + 1
        return str(uuid.uuid4())[:8]

    def unregister_session(self, ip: str):
        """
        Unregister a session.
        """
        self.active_sessions = max(0, self.active_sessions - 1)
        if ip in self.sessions_per_ip:
            self.sessions_per_ip[ip] = max(0, self.sessions_per_ip[ip] - 1)
            if self.sessions_per_ip[ip] == 0:
                del self.sessions_per_ip[ip]

    def ban_ip(self, ip: str, duration: int = None):
        """Manual ban."""
        if duration is None:
            duration = self.ban_duration
        self.banned_ips[ip] = time.time() + duration
