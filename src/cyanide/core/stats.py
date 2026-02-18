import time
from collections import Counter
from typing import Any, Dict, List


class StatsManager:
    """Manages real-time honeypot statistics and metrics."""

    def __init__(self):
        self.start_time = time.time()
        self.active_sessions = 0
        self.total_sessions = 0

        # Counters
        self.ips = Counter()
        self.usernames = Counter()
        self.passwords = Counter()
        self.commands = Counter()
        self.protocols = Counter()
        self.honeytoken_triggers = Counter()
        self.malware_scans = Counter()
        self.malicious_files = Counter()
        self.dns_cache_hits = 0
        self.dns_cache_misses = 0

        # Recent activity (FIFO)
        self.recent_commands: List[Dict[str, Any]] = []
        self.max_recent = 50

    def on_connect(self, protocol: str, ip: str):
        self.active_sessions += 1
        self.total_sessions += 1
        self.protocols[protocol] += 1
        self.ips[ip] += 1

    def on_disconnect(self, protocol: str, ip: str):
        self.active_sessions = max(0, self.active_sessions - 1)

    def on_auth(self, protocol: str, ip: str, username: str, password: str, success: bool):
        self.usernames[username] += 1
        self.passwords[password] += 1

    def on_command(self, protocol: str, ip: str, username: str, command: str):
        self.commands[command] += 1

        # Add to recent
        self.recent_commands.insert(
            0,
            {
                "timestamp": time.time(),
                "protocol": protocol,
                "ip": ip,
                "username": username,
                "command": command,
            },
        )
        if len(self.recent_commands) > self.max_recent:
            self.recent_commands.pop()

    def on_honeytoken(self, path: str, ip: str):
        self.honeytoken_triggers[path] += 1

    def on_malware(self, filename: str, is_malicious: bool):
        self.malware_scans[filename] += 1
        if is_malicious:
            self.malicious_files[filename] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics as a dictionary."""
        uptime = int(time.time() - self.start_time)
        return {
            "uptime_seconds": uptime,
            "active_sessions": self.active_sessions,
            "total_sessions": self.total_sessions,
            "top_ips": dict(self.ips.most_common(10)),
            "top_usernames": dict(self.usernames.most_common(10)),
            "top_commands": dict(self.commands.most_common(10)),
            "recent_commands": self.recent_commands[:10],
            "honeytoken_hits": dict(self.honeytoken_triggers),
            "malware_scans": sum(self.malware_scans.values()),
            "malicious_detected": sum(self.malicious_files.values()),
        }

    def to_prometheus(self) -> str:
        """Format metrics for Prometheus."""
        lines = []
        lines.append("# HELP cyanide_active_sessions Number of currently active sessions")
        lines.append("# TYPE cyanide_active_sessions gauge")
        lines.append(f"cyanide_active_sessions {self.active_sessions}")

        lines.append("# HELP cyanide_total_sessions_total Total number of connections since start")
        lines.append("# TYPE cyanide_total_sessions_total counter")
        lines.append(f"cyanide_total_sessions_total {self.total_sessions}")

        lines.append("# HELP cyanide_uptime_seconds Honeypot uptime in seconds")
        lines.append("# TYPE cyanide_uptime_seconds counter")
        lines.append(f"cyanide_uptime_seconds {int(time.time() - self.start_time)}")

        # Protocols
        for proto, count in self.protocols.items():
            lines.append(f'cyanide_protocols_total{{protocol="{proto}"}} {count}')

        # Honeytokens
        for path, count in self.honeytoken_triggers.items():
            lines.append(f'cyanide_honeytoken_hits_total{{path="{path}"}} {count}')

        # Malware
        lines.append(f"cyanide_malware_scans_total {sum(self.malware_scans.values())}")
        lines.append(f"cyanide_malicious_files_total {sum(self.malicious_files.values())}")

        # DNS Cache
        lines.append("# HELP cyanide_dns_cache_hits_total Total DNS cache hits")
        lines.append("# TYPE cyanide_dns_cache_hits_total counter")
        lines.append(f"cyanide_dns_cache_hits_total {self.dns_cache_hits}")

        lines.append("# HELP cyanide_dns_cache_misses_total Total DNS cache misses")
        lines.append("# TYPE cyanide_dns_cache_misses_total counter")
        lines.append(f"cyanide_dns_cache_misses_total {self.dns_cache_misses}")

        return "\n".join(lines) + "\n"
