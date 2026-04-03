import time
from collections import Counter
from typing import Any, Dict, List


class StatsManager:
    """Manages real-time honeypot statistics and metrics."""

    def __init__(self):
        self.start_time = time.time()
        self.active_sessions = 0
        self.total_sessions = 0

        self.ips: Counter[str] = Counter()
        self.unique_ips: set[str] = set()
        self.usernames: Counter[str] = Counter()
        self.passwords: Counter[str] = Counter()
        self.commands: Counter[str] = Counter()
        self.protocols: Counter[str] = Counter()
        self.honeytoken_triggers: Counter[str] = Counter()
        self.malware_scans: Counter[str] = Counter()
        self.malicious_files: Counter[str] = Counter()
        self.dns_cache_hits = 0
        self.dns_cache_misses = 0

        self.command_not_found: Counter[str] = Counter()
        self.path_stats: Counter[str] = Counter()

        self.auth_success = 0
        self.auth_failures = 0

        self.file_ops: Counter[str] = Counter()

        self.bytes_in = 0
        self.bytes_out = 0

        self.recent_commands: List[Dict[str, Any]] = []
        self.max_recent = 50

    def on_connect(self, protocol: str, ip: str):
        self.active_sessions += 1
        self.total_sessions += 1
        self.protocols[protocol] += 1
        self.ips[ip] += 1
        self.unique_ips.add(ip)

    def on_disconnect(self):
        self.active_sessions = max(0, self.active_sessions - 1)

    def on_auth(self, username: str, password: str, success: bool):
        self.usernames[username] += 1
        self.passwords[password] += 1
        if success:
            self.auth_success += 1
        else:
            self.auth_failures += 1

    def on_command(self, protocol: str, ip: str, username: str, command: str):
        self.commands[command] += 1

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

    def on_honeytoken(self, path: str):
        self.honeytoken_triggers[path] += 1

    def on_malware(self, filename: str, is_malicious: bool):
        self.malware_scans[filename] += 1
        if is_malicious:
            self.malicious_files[filename] += 1

    def on_file_op(self, operation: str, path: str):
        """Track file operations (read, write, delete)."""
        self.file_ops[operation] += 1
        self.path_stats[path] += 1

    def on_command_not_found(self, cmd: str):
        """Track 'command not found' events (confusion metric)."""
        self.command_not_found[cmd] += 1

    def on_traffic(self, direction: str, size: int):
        """Track traffic metrics."""
        if direction == "in":
            self.bytes_in += size
        else:
            self.bytes_out += size

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics as a dictionary."""
        uptime = int(time.time() - self.start_time)
        return {
            "uptime_seconds": uptime,
            "active_sessions": self.active_sessions,
            "total_sessions": self.total_sessions,
            "unique_attackers": len(self.unique_ips),
            "auth_success": self.auth_success,
            "auth_failures": self.auth_failures,
            "top_ips": dict(self.ips.most_common(10)),
            "top_usernames": dict(self.usernames.most_common(10)),
            "top_commands": dict(self.commands.most_common(10)),
            "recent_commands": self.recent_commands[:10],
            "honeytoken_hits": dict(self.honeytoken_triggers),
            "malware_scans": sum(self.malware_scans.values()),
            "malicious_detected": sum(self.malicious_files.values()),
            "file_operations": dict(self.file_ops),
            "top_file_paths": dict(self.path_stats.most_common(10)),
            "command_not_found_counts": dict(self.command_not_found.most_common(10)),
            "total_command_not_found": sum(self.command_not_found.values()),
            "traffic": {"bytes_in": self.bytes_in, "bytes_out": self.bytes_out},
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

        lines.append("# HELP cyanide_unique_attackers_total Total number of unique attacker IPs")
        lines.append("# TYPE cyanide_unique_attackers_total counter")
        lines.append(f"cyanide_unique_attackers_total {len(self.unique_ips)}")

        lines.append("# HELP cyanide_uptime_seconds Honeypot uptime in seconds")
        lines.append("# TYPE cyanide_uptime_seconds counter")
        lines.append(f"cyanide_uptime_seconds {int(time.time() - self.start_time)}")

        lines.append("# HELP cyanide_auth_success_total Total successful login attempts")
        lines.append("# TYPE cyanide_auth_success_total counter")
        lines.append(f"cyanide_auth_success_total {self.auth_success}")

        lines.append("# HELP cyanide_auth_failures_total Total failed login attempts")
        lines.append("# TYPE cyanide_auth_failures_total counter")
        lines.append(f"cyanide_auth_failures_total {self.auth_failures}")

        lines.append("# HELP cyanide_protocols_total Total connections per protocol")
        lines.append("# TYPE cyanide_protocols_total counter")
        for proto, count in self.protocols.items():
            lines.append(f'cyanide_protocols_total{{protocol="{proto}"}} {count}')

        lines.append("# HELP cyanide_honeytoken_hits_total Total hits on honeytoken paths")
        lines.append("# TYPE cyanide_honeytoken_hits_total counter")
        for path, count in self.honeytoken_triggers.items():
            lines.append(f'cyanide_honeytoken_hits_total{{path="{path}"}} {count}')

        lines.append("# HELP cyanide_malware_scans_total Total malware scans performed")
        lines.append("# TYPE cyanide_malware_scans_total counter")
        lines.append(f"cyanide_malware_scans_total {sum(self.malware_scans.values())}")

        lines.append("# HELP cyanide_malicious_files_total Total malicious files detected")
        lines.append("# TYPE cyanide_malicious_files_total counter")
        lines.append(f"cyanide_malicious_files_total {sum(self.malicious_files.values())}")

        lines.append("# HELP cyanide_file_ops_total Total filesystem operations by type")
        lines.append("# TYPE cyanide_file_ops_total counter")
        for op, count in self.file_ops.items():
            lines.append(f'cyanide_file_ops_total{{op="{op}"}} {count}')

        lines.append("# HELP cyanide_traffic_bytes_in_total Total inbound traffic in bytes")
        lines.append("# TYPE cyanide_traffic_bytes_in_total counter")
        lines.append(f"cyanide_traffic_bytes_in_total {self.bytes_in}")

        lines.append("# HELP cyanide_traffic_bytes_out_total Total outbound traffic in bytes")
        lines.append("# TYPE cyanide_traffic_bytes_out_total counter")
        lines.append(f"cyanide_traffic_bytes_out_total {self.bytes_out}")

        lines.append("# HELP cyanide_command_not_found_total Total count of commands not found")
        lines.append("# TYPE cyanide_command_not_found_total counter")
        lines.append(f"cyanide_command_not_found_total {sum(self.command_not_found.values())}")

        for cmd, count in self.command_not_found.items():
            lines.append(f'cyanide_missing_commands_total{{command="{cmd}"}} {count}')

        for path, count in self.path_stats.items():
            lines.append(f'cyanide_path_access_total{{path="{path}"}} {count}')

        lines.append("# HELP cyanide_dns_cache_hits_total Total DNS cache hits")
        lines.append("# TYPE cyanide_dns_cache_hits_total counter")
        lines.append(f"cyanide_dns_cache_hits_total {self.dns_cache_hits}")

        lines.append("# HELP cyanide_dns_cache_misses_total Total DNS cache misses")
        lines.append("# TYPE cyanide_dns_cache_misses_total counter")
        lines.append(f"cyanide_dns_cache_misses_total {self.dns_cache_misses}")

        return "\n".join(lines) + "\n"
