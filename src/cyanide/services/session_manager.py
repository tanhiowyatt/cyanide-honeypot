import time
import uuid
from typing import Any, Dict, List, Optional


class SessionManager:
    """
    Manages active session counts and enforces connection limits.
    """

    # Function 190: Initializes the class instance and its attributes.
    def __init__(self, config: Dict, logger):
        self.max_sessions = config.get("max_sessions", 100)
        self.max_sessions_per_ip = config.get("max_sessions_per_ip", 5)
        self.session_timeout = config.get("session_timeout", 300)

        self.max_connections_per_minute = config.get("rate_limit", {}).get(
            "max_connections_per_minute", 60
        )
        self.ban_duration = config.get("rate_limit", {}).get("ban_duration", 3600)

        self.active_sessions = 0
        self.sessions_per_ip: Dict[str, int] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}

        self.banned_ips: Dict[str, float] = {}
        self.connection_history: Dict[str, List[float]] = {}
        self.logger = logger

    # Function 191: Performs operations related to can accept.
    def can_accept(self, ip: str) -> tuple[bool, str]:
        """
        Check if a connection from IP can be accepted.
        Returns: (accepted, rejection_reason)
        """
        now = time.time()
        if ip in self.banned_ips:
            if now < self.banned_ips[ip]:
                return False, "ip_banned"
            else:
                del self.banned_ips[ip]

        history = self.connection_history.get(ip, [])
        history = [t for t in history if now - t < 60]
        self.connection_history[ip] = history

        if len(history) >= self.max_connections_per_minute:
            self.banned_ips[ip] = now + self.ban_duration
            self.logger.log_event(
                "system",
                "ip_banned",
                {"src_ip": ip, "ban_duration": self.ban_duration, "reason": "rate_limit_exceeded"},
            )
            return False, "rate_limit_exceeded (banned)"

        self.connection_history[ip].append(now)

        if self.active_sessions >= self.max_sessions:
            return False, "global_limit_reached"

        per_ip_count = self.sessions_per_ip.get(ip, 0)
        if per_ip_count >= self.max_sessions_per_ip:
            return False, "per_ip_limit_reached"

        return True, ""

    # Function 192: Performs operations related to register session.
    def register_session(self, ip: str, session_id: Optional[str] = None) -> str:
        """
        Register a new session and return its ID.
        """
        self.active_sessions += 1
        self.sessions_per_ip[ip] = self.sessions_per_ip.get(ip, 0) + 1
        if session_id is None:
            session_id = str(uuid.uuid4())[:8]

        self.sessions[session_id] = {
            "ip": ip,
            "start_time": time.time(),
            "commands": 0,
            "file_ops": 0,
        }
        return session_id

    # Function 193: Performs operations related to unregister session.
    def unregister_session(self, session_id: str):
        """
        Unregister a session and cleanup stats.
        """
        if session_id not in self.sessions:
            return

        session_data = self.sessions.pop(session_id)
        ip = session_data["ip"]

        self.active_sessions = max(0, self.active_sessions - 1)
        if ip in self.sessions_per_ip:
            self.sessions_per_ip[ip] = max(0, self.sessions_per_ip[ip] - 1)
            if self.sessions_per_ip[ip] == 0:
                del self.sessions_per_ip[ip]

    def record_command(self, session_id: str):
        """Increment command counter for a session."""
        if session_id in self.sessions:
            self.sessions[session_id]["commands"] += 1

    def record_file_op(self, session_id: str):
        """Increment file operation counter for a session."""
        if session_id in self.sessions:
            self.sessions[session_id]["file_ops"] += 1

    def get_session_stats(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return session statistics."""
        return self.sessions.get(session_id)

    # Function 194: Performs operations related to ban ip.
    def ban_ip(self, ip: str, duration: Optional[int] = None):
        """Manual ban."""
        if duration is None:
            duration = self.ban_duration
        self.banned_ips[ip] = time.time() + duration
