"""
Advanced SSH/Telnet Honeypot Server Implementation.
"""

import asyncio
import json
import os
import random
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import asyncssh
from prometheus_client import generate_latest

from cyanide import CyanideLogger
from cyanide.core.emulator import ShellEmulator
from cyanide.network.tcp_proxy import TCPProxy
from cyanide.services.analytics import AnalyticsService
from cyanide.services.quarantine import QuarantineService
from cyanide.services.session_manager import SessionManager
from cyanide.services.telnet_handler import TelnetHandler
from cyanide.vfs.provider import FakeFilesystem

from .async_logger import AsyncLogger
from .defaults import DEFAULT_METADATA
from .fs_utils import resolve_fs_path, validate_fs_config
from .sftp import CyanideSFTPServer
from .stats import StatsManager
from .telemetry import setup_telemetry
from .vm_pool import VMPool
from .vt_scanner import VTScanner


class ServiceRegistry:
    def __init__(
        self,
        session: "SessionManager",
        quarantine: "QuarantineService",
        analytics: "AnalyticsService",
        telnet: Any = None,
    ):
        self.session = session
        self.quarantine = quarantine
        self.analytics = analytics
        self.telnet = telnet


class HoneypotServer:
    """Main honeypot server orchestrating SSH, Telnet, and MySQL services."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize honeypot server with configuration."""
        self.config = config
        self.stats = StatsManager()
        self.tracer = setup_telemetry("cyanide-honeypot", config.get("otel", {}), "1.0.0")

        # --- Initialize Logger ---
        log_dir = config.get("logging", {}).get("directory", "var/log/cyanide")
        self.logger = CyanideLogger(log_dir)

        # --- Initialize Services ---
        # 1. Session Manager
        session_mgr = SessionManager(config)

        # 2. Quarantine Service
        quarantine_svc = QuarantineService(config, self.logger)
        # Pass VTScanner to QuarantineService
        # VirusTotal
        vt_key = config.get("virustotal", {}).get("api_key", "")
        self.vt_scanner = VTScanner(vt_key)
        quarantine_svc.set_scanner(self.vt_scanner)

        # 3. Analytics Service
        analytics_svc = AnalyticsService(config, self.logger)

        # Register Services (telnet=None initially due to circular dependency)
        self.services = ServiceRegistry(
            session=session_mgr,
            quarantine=quarantine_svc,
            analytics=analytics_svc,
            telnet=None,
        )

        # 4. Telnet Handler
        telnet_handler = TelnetHandler(self, config)

        # Update declared telnet service
        self.services.telnet = telnet_handler

        # Backward compatibility / Shortcuts for internal use if needed
        self.ml_enabled = analytics_svc.ml_enabled
        self.ml_filter = analytics_svc.ml_filter

        self.ssh_server: Any = None
        self.telnet_server: Any = None
        self.metrics_server: Any = None
        self.background_tasks: List[asyncio.Task] = []

        self.async_logger = AsyncLogger()

        # OS Profile and Filesystem config
        # OS Profile and Filesystem config
        profile_name = config.get("os_profile", "ubuntu_22_04")

        # Use new flexible resolution logic
        self.fs_yaml_path = resolve_fs_path(profile_name)

        # Initial profile from fallback constants
        self.profile = DEFAULT_METADATA.copy()

        # Load metadata from YAML to ensure self.profile is accurate for banners/uname
        if self.fs_yaml_path and os.path.exists(self.fs_yaml_path):
            is_valid, err = validate_fs_config(Path(self.fs_yaml_path))
            if not is_valid:
                print(f"[!] Invalid filesystem config: {err}")
                # Fallback to safe default? Or allow it to crash later?
                # User requirement says "Provide clear error messages", which we did.

            try:
                import yaml

                with open(self.fs_yaml_path, "r") as f:
                    y_data = yaml.safe_load(f)
                    if y_data and "metadata" in y_data:
                        self.profile.update(y_data["metadata"])
                        print(f"[*] Initialized profile from {self.fs_yaml_path} metadata")
            except Exception as e:
                print(f"[!] Error loading metadata from {self.fs_yaml_path}: {e}")

        self.users = config.get("users", [])

    @property
    def active_sessions(self):
        """Compatibility property for old code."""
        return self.services.session.active_sessions

    def _analyze_command(self, cmd, username, src_ip, session_id, protocol, is_bot=False):
        """Delegated to AnalyticsService."""
        with self.tracer.start_as_current_span("analyze_command") as span:
            span.set_attribute("command.body", cmd)
            span.set_attribute("user.name", username)
            span.set_attribute("net.peer.ip", src_ip)
            span.set_attribute("session.id", session_id)
            span.set_attribute("net.protocol.name", protocol)
            span.set_attribute("bot.detected", is_bot)
            self.services.analytics.analyze_command(
                cmd, username, src_ip, session_id, protocol, is_bot=is_bot
            )

    async def log_geoip(self, session_id, ip, protocol):
        """Delegated to AnalyticsService."""
        await self.services.analytics.log_geoip(session_id, ip, protocol)

    def _load_users(self, config_users):
        """Load user credentials from configuration."""
        return config_users

    def is_valid_user(self, username, password):
        """Validate user credentials against configured users."""
        for user in self.users:
            if user["user"] == username and user["pass"] == password:
                return True
        return False

    def _fs_audit_hook(self, action, path, session_id="unknown", src_ip="unknown"):
        """Callback for filesystem auditing."""
        try:
            loop = asyncio.get_running_loop()

            # Honeytoken Tripwires
            HONEYTOKENS = [
                "/home/admin/secret.conf",
                "/home/admin/flag.txt",
                "/etc/shadow",
                "/var/spool/cron/crontabs/root",
                "/root/flag.txt",
                "/root/secret.conf",
                "/root/.ssh/id_rsa",
            ]

            event_type = "fs_audit"
            if str(path) in HONEYTOKENS:
                event_type = "CRITICAL_ALERT"
                self.stats.on_honeytoken(str(path), src_ip)

            loop.create_task(
                self.logger.log_event_async(
                    {
                        "event": event_type,
                        "action": action,
                        "path": str(path),
                        "session_id": session_id,
                        "src_ip": src_ip,
                    }
                )
            )
        except RuntimeError:
            pass

    def get_filesystem(self, session_id="unknown", src_ip="unknown"):
        """Create a fresh filesystem instance for a new session."""

        def audit_hook(action, path):
            self._fs_audit_hook(action, path, session_id, src_ip)

        if self.fs_yaml_path and os.path.isfile(self.fs_yaml_path):
            try:
                from cyanide.fs.yaml_fs import load_fs

                root, metadata = load_fs(self.fs_yaml_path)
                self.logger.log_event(
                    session_id,
                    "system_status",
                    {"message": f"Loaded filesystem from {self.fs_yaml_path}"},
                )

                # If YAML has metadata, we can use it to override/set profile for this session
                # or just use the server default. For consistency, we use YAML metadata if it matches.
                current_profile = self.profile.copy()
                if metadata:
                    current_profile.update(metadata)

                fs = FakeFilesystem(root=root, audit_callback=audit_hook, profile=current_profile)
                return fs
            except Exception as e:
                self.logger.log_event(
                    session_id, "error", {"message": f"Error loading YAML FS: {e}"}
                )
                traceback.print_exc()
        return FakeFilesystem(audit_callback=audit_hook, profile=self.profile)

    async def _scan_and_log(
        self, filename: str, content: bytes, session_id="unknown", src_ip="unknown"
    ):
        """Background task to scan file and log results."""
        try:
            result = await self.vt_scanner.scan(content, filename)
            if result:
                await self.logger.log_event_async(
                    {
                        "event": "malware_scan",
                        "session_id": session_id,
                        "src_ip": src_ip,
                        "filename": filename,
                        "sha256": result.get("sha256"),
                        "malicious": result.get("malicious"),
                        "label": result.get("label"),
                        "vt_link": result.get("link"),
                    }
                )
                self.stats.on_malware(filename, result.get("malicious", False))
        except Exception as e:
            await self.logger.log_event_async(
                {
                    "event": "scan_error",
                    "session_id": session_id,
                    "src_ip": src_ip,
                    "message": f"Scan Error: {e}",
                }
            )

    def save_quarantine_file(
        self, filename: str, content: bytes, session_id="unknown", src_ip="unknown"
    ):
        """Delegated to QuarantineService."""
        return asyncio.run(
            self.services.quarantine.save_file(filename, content, session_id, src_ip)
        )

    def _log_tty(self, session_obj, direction: str, data: str):
        """Dual format logging: JSONL for reading + Timing/TS for scriptreplay."""
        if direction != "OUT" and not hasattr(session_obj, "tty_log_path_jsonl"):
            return

        # 1. JSONL Log
        if hasattr(session_obj, "tty_log_path_jsonl"):
            try:
                now = time.time()
                # Convert to string if bytes
                if isinstance(data, bytes):
                    readable_data = data.decode("utf-8", "ignore")
                else:
                    readable_data = data

                entry = {"timestamp": now, "direction": direction, "data": readable_data}
                self.async_logger.log(session_obj.tty_log_path_jsonl, json.dumps(entry) + "\n")
            except Exception as e:
                self.logger.log_event(
                    "system", "tty_error", {"message": f"Error saving JSONL TTY: {e}"}
                )

        # 2. Timing + TypeScript Log (scriptreplay)
        if hasattr(session_obj, "tty_log_path") and hasattr(session_obj, "tty_timing_path"):
            try:
                now = time.time()
                elapsed = now - session_obj.last_log_time
                session_obj.last_log_time = now

                self.async_logger.log(session_obj.tty_timing_path, f"{elapsed:.6f} {len(data)}\n")

                if isinstance(data, str):
                    self.async_logger.log(session_obj.tty_log_path, data.encode(), mode="ab")
                else:
                    self.async_logger.log(session_obj.tty_log_path, data, mode="ab")
            except Exception as e:
                self.logger.log_event(
                    "system", "tty_error", {"message": f"Error saving scriptreplay TTY: {e}"}
                )

    async def start_metrics_server(self):
        """Start a lightweight HTTP server for metrics and stats."""
        metrics_conf = self.config.get("metrics", {})
        if not metrics_conf.get("enabled", True):
            return

        port = metrics_conf.get("port", 9090)

        async def handle_request(reader, writer):
            try:
                # Read request line with timeout
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                except asyncio.TimeoutError:
                    writer.close()
                    return

                if not line:
                    writer.close()
                    return

                request_parts = line.decode().split()
                if len(request_parts) < 2:
                    writer.close()
                    return

                path = request_parts[1]

                # Drain headers
                try:
                    while True:
                        header = await asyncio.wait_for(reader.readline(), timeout=1.0)
                        if header in (b"\r\n", b"\n", b""):
                            break
                except asyncio.TimeoutError:
                    pass

                if path == "/metrics":
                    content = self.stats.to_prometheus()

                    # Append ML metrics if available
                    if self.ml_enabled and self.ml_filter:
                        try:
                            ml_metrics = generate_latest().decode()
                            content += "\n" + ml_metrics
                        except Exception as e:
                            self.logger.log_event(
                                "system",
                                "metrics_error",
                                {"message": f"Error generating ML metrics: {e}"},
                            )

                    content_type = "text/plain; version=0.0.4; charset=utf-8"
                elif path == "/stats":
                    content = json.dumps(self.stats.get_stats(), indent=2)
                    content_type = "application/json"
                elif path == "/health":
                    # Check core services
                    ssh_conf = self.config.get("ssh", {})
                    telnet_conf = self.config.get("telnet", {})

                    ssh_up = self.ssh_server is not None
                    telnet_up = self.telnet_server is not None

                    is_healthy = True
                    if ssh_conf.get("enabled", True) and not ssh_up:
                        is_healthy = False
                    if telnet_conf.get("enabled", False) and not telnet_up:
                        is_healthy = False

                    status_data = {
                        "status": "healthy" if is_healthy else "unhealthy",
                        "version": "2.1.1",
                        "uptime": int(time.time() - self.stats.start_time),
                        "services": {"ssh": ssh_up, "telnet": telnet_up},
                    }
                    content = json.dumps(status_data)
                    content_type = "application/json"
                else:
                    content = "Cyanide Honeypot Metrics Server. Use /metrics, /stats or /health."
                    content_type = "text/plain"

                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(content)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                    f"{content}"
                ).encode()

                writer.write(response)
                await writer.drain()
            except Exception as e:
                self.logger.log_event(
                    "system", "metrics_handler_error", {"message": f"Metrics Handler Error: {e}"}
                )
            finally:
                writer.close()
                await writer.wait_closed()

        try:
            self.metrics_server = await asyncio.start_server(handle_request, "0.0.0.0", port)
            self.logger.log_event("system", "service_started", {"service": "metrics", "port": port})
            async with self.metrics_server:
                await self.metrics_server.serve_forever()
        except Exception as e:
            self.logger.log_event(
                "system", "metrics_server_error", {"message": f"Metrics Server Error: {e}"}
            )

    async def start(self):
        """Start all honeypot services and enter main event loop."""
        # Start Async Logger
        await self.async_logger.start()

        # Generate SSH Host Key
        ssh_key = asyncssh.generate_private_key("ssh-rsa")

        # Initialize VM Pool if needed
        self.vm_pool = VMPool(self.config)

        # Start SSH Server
        ssh_conf = self.config.get("ssh", {})
        ssh_enabled = ssh_conf.get("enabled", True)
        if ssh_enabled:
            ssh_port = ssh_conf["port"]
            backend_mode = ssh_conf.get("backend_mode", "emulated")  # emulated, proxy, pool

            if backend_mode == "emulated":
                # Anti-Fingerprinting
                # Use override from config if available, otherwise use banner from profile
                chosen_version = ssh_conf.get("version") or self.profile["ssh_banner"]
                self.logger.log_event(
                    "system", "system_status", {"message": f"SSH Banner: {chosen_version}"}
                )

                self.ssh_server = await asyncssh.listen(
                    "0.0.0.0",
                    ssh_port,
                    server_host_keys=[ssh_key],
                    server_factory=lambda: SSHServerFactory(self),
                    reuse_address=True,
                    server_version=chosen_version,
                )
                self.logger.log_event(
                    "system", "service_started", {"service": "ssh_emulated", "port": ssh_port}
                )
            elif backend_mode == "proxy" or backend_mode == "pool":
                # Use TCP Proxy for pure SSH monitoring (simplest approach for "Pure Proxy" request)
                # Or use the specific SSH Proxy implementation if we want to dissect packets?
                # The user asked for "pure telnet and ssh proxy with monitoring"
                # Our TCPProxy monitors data.
                # If pool, use selector.
                selector = self.vm_pool.get_target if backend_mode == "pool" else None
                t_host = ssh_conf.get("target_host", "127.0.0.1")
                t_port = int(ssh_conf.get("target_port", 22222))

                ssh_proxy = TCPProxy(
                    "0.0.0.0",
                    ssh_port,
                    target_host=t_host,
                    target_port=t_port,
                    protocol_name="ssh_proxy",
                    target_selector=selector,
                )
                await ssh_proxy.start()

        # Start Telnet Server
        telnet_conf = self.config.get("telnet", {})
        telnet_enabled = telnet_conf.get("enabled", False)
        if telnet_enabled:
            telnet_port = telnet_conf["port"]
            backend_mode = telnet_conf.get("backend_mode", "emulated")

            if backend_mode == "emulated":
                self.telnet_server = await asyncio.start_server(
                    self.services.telnet.handle_connection,
                    "0.0.0.0",
                    telnet_port,
                    reuse_address=True,
                )
                self.logger.log_event(
                    "system", "service_started", {"service": "telnet_emulated", "port": telnet_port}
                )
            elif backend_mode == "pool" or backend_mode == "proxy":
                selector = self.vm_pool.get_target if backend_mode == "pool" else None
                t_host = telnet_conf.get("target_host", "127.0.0.1")
                t_port = int(telnet_conf.get("target_port", 2323))

                telnet_proxy = TCPProxy(
                    "0.0.0.0",
                    telnet_port,
                    target_host=t_host,
                    target_port=t_port,
                    protocol_name="telnet_proxy",
                    target_selector=selector,
                )
                await telnet_proxy.start()

        # Start SMTP Proxy (Forwarding)
        smtp_conf = self.config.get("smtp", {})
        if smtp_conf.get("enabled", False):
            try:
                smtp_proxy = TCPProxy(
                    "0.0.0.0",
                    int(smtp_conf.get("listen_port", 25)),
                    smtp_conf.get("target_host", "127.0.0.1"),
                    int(smtp_conf.get("target_port", 2525)),
                    protocol_name="smtp",
                )
                await smtp_proxy.start()
            except Exception as e:
                self.logger.log_event(
                    "system", "smtp_proxy_error", {"message": f"Failed to start SMTP Proxy: {e}"}
                )

        # Start Metrics Server
        self.background_tasks.append(asyncio.create_task(self.start_metrics_server()))

        # Start Cleanup Task
        self.background_tasks.append(asyncio.create_task(self._cleanup_loop()))

        # Start Stats Logging Task
        self.background_tasks.append(asyncio.create_task(self._stats_logging_loop()))

        # Keep running
        try:
            self._stop_event = asyncio.Event()
            await self._stop_event.wait()
        except asyncio.CancelledError:
            await self.stop()

    async def stop(self):
        """Stop all services."""
        self.logger.log_event("system", "system_status", {"message": "Stopping Honeypot Server..."})

        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()

        if self.ssh_server:
            self.ssh_server.close()
            await self.ssh_server.wait_closed()
        if self.telnet_server:
            self.telnet_server.close()
            await self.telnet_server.wait_closed()
        if self.metrics_server:
            self.metrics_server.close()
            await self.metrics_server.wait_closed()

        await self.async_logger.stop()

        if hasattr(self, "_stop_event"):
            self._stop_event.set()

    async def _stats_logging_loop(self):
        """Periodically log statistics to cyanide-stats.json."""
        while True:
            try:
                # Log current stats
                stats_data = self.stats.get_stats()
                self.logger.log_event("system", "stats", stats_data)
            except Exception as e:
                self.logger.log_event("system", "error", {"message": f"Stats Logging Error: {e}"})

            # Log every 60 seconds (or 10 for demo/dev if needed, but 60 is standard)
            await asyncio.sleep(60)

    async def _cleanup_loop(self):
        """Background task for automatic file cleanup."""
        # Initial delay to let things start
        await asyncio.sleep(60)

        from .cleanup import CleanupManager

        manager = CleanupManager(self.config)

        if not manager.enabled:
            self.logger.log_event("system", "cleanup_status", {"message": "Cleanup: Disabled"})
            return

        self.logger.log_event(
            "system",
            "cleanup_status",
            {
                "message": f"Cleanup: Enabled (Every {manager.interval}s, older than {manager.retention_days}d)"
            },
        )

        while True:
            try:
                stats = manager.cleanup_files()
                if stats["deleted"] > 0:
                    await self.logger.log_event_async(
                        {
                            "event": "system_cleanup",
                            "deleted": stats["deleted"],
                            "bytes_freed": stats["bytes_freed"],
                        }
                    )
            except Exception as e:
                self.logger.log_event("system", "cleanup_error", {"message": f"Cleanup Error: {e}"})

            await asyncio.sleep(manager.interval)

    async def handle_telnet(self, reader, writer):
        """Deprecated. Use services.telnet.handle_connection."""
        await self.services.telnet.handle_connection(reader, writer)


class SSHServerFactory(asyncssh.SSHServer):
    """SSH server factory."""

    def __init__(self, honeypot: HoneypotServer):
        self.honeypot = honeypot
        self.src_ip = "unknown"
        self.src_port = 0
        self.fs = None
        self.conn_id = str(uuid.uuid4())[:8]

    def connection_made(self, conn):
        self.src_ip = conn.get_extra_info("peername")[0]
        self.src_port = conn.get_extra_info("peername")[1]

        with self.honeypot.tracer.start_as_current_span("ssh_connection_setup") as span:
            span.set_attribute("net.peer.ip", self.src_ip)
            span.set_attribute("net.peer.port", self.src_port)

            # Check limits via SessionManager
            accepted, reason = self.honeypot.services.session.can_accept(self.src_ip)
            if not accepted:
                span.set_attribute("error", True)
                span.set_attribute("rejection_reason", reason)
                self.honeypot.logger.log_event(
                    "system", "connection_rejected", {"src_ip": self.src_ip, "reason": reason}
                )
                conn.close()
                return

            self.honeypot.services.session.register_session(self.src_ip, "ssh")

            # Create a filesystem instance for this connection with IP context
            self.fs = self.honeypot.get_filesystem(
                session_id="conn_" + self.conn_id, src_ip=self.src_ip
            )

    def connection_lost(self, exc):
        # Transport level cleanup - handle leaks here
        self.honeypot.services.session.unregister_session(self.src_ip)
        self.honeypot.logger.log_event(
            "system",
            "ssh_connection_lost",
            {"src_ip": self.src_ip, "active_sessions": self.honeypot.active_sessions},
        )

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        success = self.honeypot.is_valid_user(username, password)
        asyncio.create_task(
            self.honeypot.logger.log_event_async(
                {
                    "event": "auth",
                    "protocol": "ssh",
                    "session_id": "conn_" + self.conn_id,
                    "src_ip": self.src_ip,
                    "username": username,
                    "password": password,
                    "success": success,
                }
            )
        )
        return success

    def sftp_factory(self, channel):
        """Create SFTP server instance sharing the connection's filesystem."""

        # Use conn_id for SFTP since it's pre-shell
        def q_hook(f, c):
            self.honeypot.save_quarantine_file(f, c, "sftp_" + self.conn_id, self.src_ip)

        return CyanideSFTPServer(channel, self.fs, q_hook)

    def subsystem_requested(self, subsystem):  # type: ignore
        if subsystem == "sftp":
            return self.sftp_factory
        return super().subsystem_requested(subsystem)  # type: ignore

    def session_requested(self):
        return SSHSession(self.honeypot, self.fs, self.src_ip, self.src_port)


class SSHSession(asyncssh.SSHServerSession):
    """SSH session handler."""

    def __init__(self, honeypot: HoneypotServer, fs: FakeFilesystem, src_ip, src_port):
        self.honeypot = honeypot
        self.fs = fs
        self.src_ip = src_ip
        self.src_port = src_port
        self.session_id = str(uuid.uuid4())[:8]
        self.commands: List[str] = []
        self.start_time = time.time()
        self.client_version = "unknown"
        self.username = "root"
        self.buf = ""
        self.shell: Optional[ShellEmulator] = None
        self.last_log_time = time.time()
        # Prompt is dynamic now
        # Biometrics
        self.keystrokes: List[float] = []  # List of timestamps
        # Traffic
        self.bytes_in = 0
        self.bytes_out = 0

    def connection_made(self, channel):
        self.channel = channel
        conn = channel.get_connection()
        self.username = conn.get_extra_info("username") or "root"
        self.client_version = conn.get_extra_info("client_version") or "unknown"

        self.honeypot.stats.on_connect("ssh", self.src_ip)

        # GeoIP Lookup
        asyncio.create_task(self.honeypot.log_geoip(self.session_id, self.src_ip, "ssh"))

        # SSH Fingerprinting
        # Extract negotiated algorithms (HASSH-like data)
        try:
            # Helper for extraction
            def get_val(key, internal_attr=None, decode=False):
                val = conn.get_extra_info(key)
                if val is not None:
                    return val
                if internal_attr:
                    val = getattr(conn, internal_attr, None)
                    if val is not None:
                        if decode and isinstance(val, bytes):
                            return val.decode("utf-8", "ignore")
                        return val
                return "unknown"

            # KEX
            kex = get_val("kex")

            # Key Algo
            key_algo = get_val("server_host_key")
            if key_algo == "unknown":
                hk = getattr(conn, "_server_host_key", None)
                if hk and hasattr(hk, "algorithm"):
                    key_algo = (
                        hk.algorithm.decode()
                        if isinstance(hk.algorithm, bytes)
                        else str(hk.algorithm)
                    )

            # Cipher
            cipher = get_val("cipher", "_enc_alg_cs", decode=True)
            if cipher == "unknown":
                # Chacha20 poly1305 often stored in mac field in local implementations
                mac_raw = getattr(conn, "_mac_alg_cs", None)
                if mac_raw and b"chacha" in mac_raw:
                    cipher = mac_raw.decode()

            # MAC
            mac = get_val("mac", "_mac_alg_cs", decode=True)

            # Compression
            compression = get_val("compression", "_compress_alg_cs", decode=True)
            if compression == "unknown":
                if getattr(conn, "_compress_after_auth", False):
                    compression = "zlib@openssh.com"
                else:
                    compression = "none"

            fingerprint = {
                "kex": kex,
                "key_algo": key_algo,
                "cipher": cipher,
                "mac": mac,
                "compression": compression,
            }

            asyncio.create_task(
                self.honeypot.logger.log_event_async(
                    {
                        "event": "client_fingerprint",
                        "session_id": self.session_id,
                        "src_ip": self.src_ip,
                        "protocol": "ssh",
                        "fingerprint": fingerprint,
                        "client_version": self.client_version,
                    }
                )
            )
        except Exception:
            pass

    def connection_lost(self, exc):
        """Log session disconnect."""
        reason = "clean"
        if exc:
            reason = f"error: {exc}"

        self.honeypot.stats.on_disconnect("ssh", self.src_ip)

        asyncio.create_task(
            self.honeypot.logger.log_event_async(
                {
                    "event": "session_disconnect",
                    "session_id": self.session_id,
                    "src_ip": self.src_ip,
                    "reason": reason,
                }
            )
        )

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        """Log terminal resize events (SIGWINCH)."""
        asyncio.create_task(
            self.honeypot.logger.log_event_async(
                {
                    "event": "window_resize",
                    "session_id": self.session_id,
                    "src_ip": self.src_ip,
                    "width": width,
                    "height": height,
                }
            )
        )
        if self.shell:
            # Propagate
            pass

    def shell_requested(self):
        # Use shared FS
        def q_hook(f, c):
            self.honeypot.services.quarantine.save_file(f, c, self.session_id, self.src_ip)

        self.shell = ShellEmulator(
            self.fs, self.username, quarantine_callback=q_hook, config=self.honeypot.config
        )
        return True

    def _get_prompt(self):
        if not self.shell:
            return "$ "
        cwd = self.shell.cwd
        if cwd.startswith(f"/home/{self.username}"):
            cwd = cwd.replace(f"/home/{self.username}", "~", 1)
        elif self.username == "root" and cwd.startswith("/root"):
            cwd = cwd.replace("/root", "~", 1)
        return f"{self.username}@server:{cwd}$ "

    def session_started(self):
        self._ensure_tty_log()
        if self.shell:
            # self.channel.write(f"Welcome into {self.username} shell\r\n")
            self.channel.write(self._get_prompt())

    def _ensure_tty_log(self):
        # Setup TTY logging (scriptreplay + JSONL)
        folder_name = f"ssh_{self.src_ip}_{self.session_id}"
        log_dir = Path(self.honeypot.logger.log_dir) / "tty" / folder_name
        log_dir.mkdir(parents=True, exist_ok=True)

        self.tty_log_path_jsonl = log_dir / f"{folder_name}.jsonl"
        self.tty_log_path = log_dir / f"{folder_name}.log"
        self.tty_timing_path = log_dir / f"{folder_name}.time"
        self.last_log_time = time.time()

        # Touch files
        open(self.tty_log_path_jsonl, "a").close()
        open(self.tty_log_path, "a").close()
        open(self.tty_timing_path, "a").close()

    def _log_tty(self, direction: str, data: str):
        self.honeypot._log_tty(self, direction, data)

    def env_received(self, name, value):
        """Log client environment variables."""
        # Convert bytes to str if needed
        if isinstance(name, bytes):
            name = name.decode("utf-8", "ignore")
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")

        asyncio.create_task(
            self.honeypot.logger.log_event_async(
                {
                    "event": "client_env",
                    "session_id": self.session_id,
                    "src_ip": self.src_ip,
                    "name": name,
                    "value": value,
                }
            )
        )
        return True

    def data_received(self, data, datatype=None):
        asyncio.create_task(self._process_input(data))

    async def _process_input(self, data):
        try:
            # Detect paste (multiple characters in one packet including newline)
            is_paste = len(data) > 1 and ("\n" in data or "\r" in data)

            # Record Keystroke Timing
            now = time.time()
            self.keystrokes.append(now)

            # Enhanced Randomized Jitter
            if random.random() < 0.1:
                delay = random.uniform(0.5, 1.5)
            else:
                delay = random.uniform(0.02, 0.15)

            await asyncio.sleep(delay)

            # Traffic
            self.bytes_in += len(data)

            if isinstance(data, bytes):
                data = data.decode("utf-8", errors="ignore")

            self._log_tty("IN", data)
            self.buf += data

            while "\n" in self.buf or "\r" in self.buf:
                if "\n" in self.buf:
                    line, self.buf = self.buf.split("\n", 1)
                elif "\r" in self.buf:
                    line, self.buf = self.buf.split("\r", 1)
                else:
                    break

                cmd = line.strip()

                # Calculate inter-keystroke timing for this command
                is_bot = is_paste
                if not is_bot and len(self.keystrokes) > 1:
                    delays = [
                        self.keystrokes[i] - self.keystrokes[i - 1]
                        for i in range(1, len(self.keystrokes))
                    ]
                    if delays:
                        avg_delay = sum(delays) / len(delays)
                        # Threshold < 10ms (0.01s)
                        if avg_delay < 0.01:
                            is_bot = True

                # Reset keystrokes for next command
                self.keystrokes = []

                if not cmd:
                    self.channel.write("\r\n" + self._get_prompt())
                    self._log_tty("OUT", "\r\n" + self._get_prompt())
                    continue

                self.commands.append(cmd)

                if cmd in ("exit", "logout"):
                    asyncio.create_task(self._close_session())
                    return

                # IOC/C2 Detection
                import re

                ipv4_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                urls_regex = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"

                iocs = []
                iocs.extend(re.findall(ipv4_regex, cmd))
                iocs.extend(re.findall(urls_regex, cmd))

                if iocs:
                    asyncio.create_task(
                        self.honeypot.logger.log_event_async(
                            {
                                "event": "ioc_detected",
                                "session_id": self.session_id,
                                "src_ip": self.src_ip,
                                "iocs": list(set(iocs)),
                                "cmd": cmd,
                            }
                        )
                    )

                # Log command immediately
                self.honeypot.stats.on_command("ssh", self.src_ip, self.username, cmd)

                asyncio.create_task(
                    self.honeypot.logger.log_command(
                        self.session_id,
                        "ssh",
                        self.src_ip,
                        self.username,
                        cmd,
                        client_version=self.client_version,
                    )
                )

                # ML Analysis with bot detection
                if self.honeypot.ml_enabled and self.honeypot.ml_filter:
                    self.honeypot._analyze_command(
                        cmd, self.username, self.src_ip, self.session_id, "ssh", is_bot=is_bot
                    )

                if self.shell:
                    stdout, stderr, rc = await self.shell.execute(cmd)
                else:
                    stdout, stderr, rc = "", "Shell not initialized\n", 1

                # Confusion Metric
                if rc == 127:  # Command not found
                    asyncio.create_task(
                        self.honeypot.logger.log_event_async(
                            {
                                "event": "command_not_found",
                                "session_id": self.session_id,
                                "src_ip": self.src_ip,
                                "cmd": cmd,
                            }
                        )
                    )

                response = stdout + stderr

                self.channel.write(response)
                self.bytes_out += len(response)
                self._log_tty("OUT", response)

                curr_prompt = self._get_prompt()
                self.channel.write(curr_prompt)
                self.bytes_out += len(curr_prompt)
                self._log_tty("OUT", curr_prompt)
                self._log_tty("IN", cmd + "\n")

        except Exception as e:
            self.honeypot.logger.log_event(
                self.session_id, "debug", {"message": f"process_input error: {e}"}
            )

    async def _close_session(self):
        await asyncio.sleep(0.01)
        self.channel.write_eof()
        self.channel.exit(0)
        self.channel.close()

    def exec_requested(self, command):
        self.honeypot.logger.log_event(
            self.session_id, "debug", {"message": f"exec_requested: {command}"}
        )
        self.commands.append(command)
        asyncio.create_task(
            self.honeypot.logger.log_command(
                self.session_id,
                "ssh",
                self.src_ip,
                self.username,
                command,
                client_version=self.client_version,
            )
        )
        asyncio.create_task(self._async_exec(command))
        return True

    async def _async_exec(self, command):
        # Use Factory
        self._ensure_tty_log()
        fs = self.fs
        shell = ShellEmulator(
            fs, self.username, quarantine_callback=self.honeypot.save_quarantine_file
        )

        # ML Analysis
        if self.honeypot.ml_enabled and self.honeypot.ml_filter:
            self.honeypot._analyze_command(
                command, self.username, self.src_ip, self.session_id, "ssh"
            )

        stdout, stderr, rc = await shell.execute(command)

        self.channel.write(stdout)
        self.honeypot._log_tty(self, "OUT", stdout)

        if stderr:
            self.channel.write_stderr(stderr)
            self.honeypot._log_tty(self, "OUT", stderr)

        self.channel.write_eof()
        await asyncio.sleep(0.01)
        self.channel.exit(rc)
        self.channel.close()

    def session_ended(self):
        duration = time.time() - self.start_time

        # Calculate Biometrics
        keystroke_stats = {}
        if len(self.keystrokes) > 1:
            diffs = []
            for i in range(1, len(self.keystrokes)):
                diffs.append(self.keystrokes[i] - self.keystrokes[i - 1])

            avg = sum(diffs) / len(diffs)

            # Variance
            variance = sum((x - avg) ** 2 for x in diffs) / len(diffs)
            std_dev = variance**0.5

            keystroke_stats = {
                "count": len(self.keystrokes),
                "avg_latency": round(avg, 4),
                "std_dev": round(std_dev, 4),
            }

        asyncio.create_task(
            self.honeypot.logger.log_event_async(
                {
                    "event": "session_end",
                    "protocol": "ssh",
                    "session_id": self.session_id,
                    "src_ip": self.src_ip,
                    "username": self.username,
                    "commands": self.commands,
                    "duration": duration,
                    "client_version": self.client_version,
                    "keystroke_metrics": keystroke_stats,
                    "traffic": {"bytes_in": self.bytes_in, "bytes_out": self.bytes_out},
                }
            )
        )
