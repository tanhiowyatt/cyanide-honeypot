"""
Advanced SSH/Telnet Honeypot Server Implementation.
"""

import asyncio
import json
import logging
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
from cyanide.vfs.engine import FakeFilesystem

from .async_logger import AsyncLogger
from .defaults import DEFAULT_METADATA
from .stats import StatsManager
from .telemetry import setup_telemetry
from .vm_pool import VMPool
from .vt_scanner import VTScanner
from .config import _CONFIG_EVENTS

# Protocol Handlers
from cyanide.vfs.scp import SCPHandler
from cyanide.vfs.rsync import RsyncHandler


class ServiceRegistry:
    # Function 37: Initializes the class instance and its attributes.
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


class CyanideServer:
    """Main honeypot server orchestrating SSH, Telnet, and MySQL services."""

    # Function 38: Initializes the class instance and its attributes.
    def __init__(self, config: Dict[str, Any]):
        """Initialize honeypot server with configuration."""
        self.config = config

        # --- 1. Initialize Logger First ---
        try:
            log_dir = config.get("logging", {}).get("directory", "var/log/cyanide")
            logging_config = config.get("logging", {})
            self.logger = CyanideLogger(
                log_dir, config.get("output", {}), logging_config=logging_config
            )
            self.logger.log_event(
                "system", "service_init_status", {"message": "Logger initialized"}
            )
            
            # Flush buffered config events
            for ev in _CONFIG_EVENTS:
                self.logger.log_event("system", ev["action"], ev["data"])
                
        except Exception as e:
            # Last resort print if logger fails
            logging.error(f"[!] CyanideServer: Failed to initialize Logger: {e}")
            raise

        # --- 2. Stats & Telemetry ---
        try:
            self.stats = StatsManager()
            self.tracer = setup_telemetry("cyanide-honeypot", config.get("otel", {}), "1.0.0")
            self.logger.log_event(
                "system", "service_init_status", {"message": "Telemetry initialized"}
            )
        except Exception as e:
            self.logger.log_event(
                "system", "service_init_error", {"service": "Telemetry", "error": str(e)}
            )
            # We might not want to crash just because telemetry failed, but Telemetry returns a proxy
            # and may have already logged via standard logging.
            # However, the previous logic raised, so we stay consistent.
            raise

        # --- Initialize Services ---
        # 1. Session Manager
        try:
            session_mgr = SessionManager(config, self.logger)
            self.logger.log_event(
                "system", "service_init_status", {"message": "SessionManager initialized"}
            )
        except Exception as e:
            self.logger.log_event(
                "system", "service_init_error", {"service": "SessionManager", "error": str(e)}
            )
            raise

        # 2. Quarantine Service
        try:
            quarantine_svc = QuarantineService(config, self.logger)
            # Pass VTScanner to QuarantineService
            # VirusTotal
            vt_key = config.get("virustotal", {}).get("api_key", "")
            self.vt_scanner = VTScanner(vt_key, self.logger)
            quarantine_svc.set_scanner(self.vt_scanner)
            self.logger.log_event(
                "system", "service_init_status", {"message": "QuarantineService initialized"}
            )
            self.logger.log_event(
                "system", "service_init_status", {"message": "VTScanner initialized"}
            )
        except Exception as e:
            self.logger.log_event(
                "system", "service_init_error", {"service": "QuarantineService", "error": str(e)}
            )
            raise

        # 3. Analytics Service
        try:
            analytics_svc = AnalyticsService(config, self.logger)
            self.logger.log_event(
                "system", "service_init_status", {"message": "AnalyticsService initialized"}
            )
        except Exception as e:
            self.logger.log_event(
                "system", "service_init_error", {"service": "AnalyticsService", "error": str(e)}
            )
            raise

        # Register Services (telnet=None initially due to circular dependency)
        try:
            self.services = ServiceRegistry(
                session=session_mgr,
                quarantine=quarantine_svc,
                analytics=analytics_svc,
                telnet=None,
            )
            self.logger.services = self.services
            self.logger.log_event(
                "system", "service_init_status", {"message": "Services registered"}
            )
        except Exception as e:
            self.logger.log_event(
                "system", "service_init_error", {"service": "ServiceRegistry", "error": str(e)}
            )
            raise

        # 4. Telnet Handler
        telnet_handler = TelnetHandler(self, config)

        # Update declared telnet service
        self.services.telnet = telnet_handler

        self.ssh_server: Any = None
        self.telnet_server: Any = None
        self.metrics_server: Any = None
        self.background_tasks: List[asyncio.Task] = []

        self.async_logger = AsyncLogger()

        self.users = config.get("users", [])

        # OS Profile and VFS root
        from .fs_utils import resolve_os_profile

        self.os_profile = resolve_os_profile(config.get("os_profile", "ubuntu"))
        self.vfs_root = config.get("vfs_root", "configs/profiles")

        # Initialize initial profile from VFS (lazy or explicitly here)
        # We create a dummy FS to grab the context metadata for banners
        try:
            temp_fs = FakeFilesystem(
                os_profile=self.os_profile, root_dir=self.vfs_root, users=self.users
            )
            self.profile = temp_fs.context.to_dict()
            self.resolved_profile_name = self.os_profile
            self.logger.log_event(
                "system",
                "vfs_init_status",
                {"message": f"Initialized VFS profile: {self.os_profile}"},
            )
        except Exception as e:
            self.logger.log_event(
                "system",
                "vfs_init_error",
                {"profile": self.os_profile, "error": str(e)},
            )
            self.profile = DEFAULT_METADATA.copy()
            self.resolved_profile_name = "ubuntu"

    # Function 40: Performs operations related to analyze command.
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

    # Function 41: Handles event logging and telemetry.
    async def log_geoip(self, session_id, ip, protocol):
        """Delegated to AnalyticsService."""
        await self.services.analytics.log_geoip(session_id, ip, protocol)

    # Function 43: Checks condition: is valid user.
    def is_valid_user(self, username, password):
        """Validate user credentials against configured users."""
        for user in self.users:
            if user["user"] == username and user["pass"] == password:
                return True
        return False

    # Function 44: Performs operations related to fs audit hook.
    def _fs_audit_hook(self, action, path, session_id="unknown", src_ip="unknown"):
        """Callback for filesystem auditing."""
        try:
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

            try:
                self.logger.log_event(
                    session_id,
                    event_type,
                    {
                        "action": action,
                        "path": str(path),
                        "src_ip": src_ip,
                    },
                )
            except Exception:
                pass
        except Exception:
            pass

    # Function 45: Retrieves filesystem data.
    def get_filesystem(self, session_id="unknown", src_ip="unknown"):
        """Create a fresh filesystem instance for a new session."""

        # Function 46: Performs operations related to audit hook.
        def audit_hook(action, path):
            self._fs_audit_hook(action, path, session_id, src_ip)

        try:
            fs = FakeFilesystem(
                os_profile=self.os_profile,
                root_dir=self.vfs_root,
                audit_callback=audit_hook,
                stats=self.stats,
                users=self.users,
            )
            return fs
        except Exception as e:
            self.logger.log_event(
                session_id, "error", {"message": f"Error initializing new VFS: {e}"}
            )
            traceback.print_exc()
            # Absolute fallback
            return FakeFilesystem(audit_callback=audit_hook, stats=self.stats)

    # Function 47: Handles event logging and telemetry.
    async def _scan_and_log(
        self, filename: str, content: bytes, session_id="unknown", src_ip="unknown"
    ):
        """Background task to scan file and log results."""
        try:
            result = await self.vt_scanner.scan(content, filename)
            if result:
                self.logger.log_event(
                    session_id,
                    "malware_scan",
                    {
                        "src_ip": src_ip,
                        "filename": filename,
                        "sha256": result.get("sha256"),
                        "malicious": result.get("malicious"),
                        "label": result.get("label"),
                        "vt_link": result.get("link"),
                    },
                )
                self.stats.on_malware(filename, result.get("malicious", False))
        except Exception as e:
            self.logger.log_event(
                session_id,
                "scan_error",
                {
                    "src_ip": src_ip,
                    "message": f"Scan Error: {e}",
                },
            )

    # Function 48: Performs operations related to save quarantine file.
    def save_quarantine_file(
        self, filename: str, content: bytes, session_id="unknown", src_ip="unknown"
    ):
        """Delegated to QuarantineService."""
        try:
            asyncio.create_task(
                self.services.quarantine.save_file(filename, content, session_id, src_ip)
            )
        except RuntimeError:
            # No loop running
            pass

    # Function 49: Handles event logging and telemetry.
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

    # Function 50: Performs operations related to start metrics server.
    async def start_metrics_server(self):
        """Start a lightweight HTTP server for metrics and stats."""
        metrics_conf = self.config.get("metrics", {})
        if not metrics_conf.get("enabled", True):
            return

        port = metrics_conf.get("port", 9090)

        # Function 51: Handles incoming request events.
        async def handle_request(reader, writer):
            try:
                # Read headers robustly
                header_data = b""
                while True:
                    try:
                        line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                        if not line or line in (b"\r\n", b"\n"):
                            break
                        header_data += line
                    except asyncio.TimeoutError:
                        break

                if not header_data:
                    writer.close()  # Added writer.close() here for consistency with original logic
                    return

                try:
                    request_line = header_data.decode("utf-8").splitlines()[0]
                    parts = request_line.split()
                    if len(parts) < 2:
                        writer.close()  # Added writer.close() here for consistency with original logic
                        return
                    path = parts[1]
                except (IndexError, UnicodeDecodeError):
                    writer.close()  # Added writer.close() here for consistency with original logic
                    return

                if path == "/metrics":
                    content = self.stats.to_prometheus()

                    # Append ML metrics if available
                    if self.services.analytics.ml_enabled and self.services.analytics.ml_pipeline:
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
                elif path.startswith("/logs"):
                    log_dir = self.config.get("logging", {}).get(
                        "directory", self.config.get("log_path", "var/log/cyanide")
                    )
                    log_base = Path(log_dir).resolve()
                    requested_subpath = path.replace("/logs", "", 1).lstrip("/")
                    target_path = (log_base / requested_subpath).resolve()

                    # Security check: ensure target is within log_base
                    if not str(target_path).startswith(str(log_base)):
                        content = "403 Forbidden: Path traversal detected."
                        content_type = "text/plain"
                    elif not target_path.exists():
                        content = f"404 Not Found: {requested_subpath}"
                        content_type = "text/plain"
                    elif target_path.is_dir():
                        # Directory listing
                        try:
                            items = os.listdir(target_path)
                            # Create a simple HTML listing
                            html_lines = [f"<h1>Index of {path}</h1><ul>"]
                            if requested_subpath:
                                parent = "/".join(path.rstrip("/").split("/")[:-1])
                                if not parent.startswith("/logs"):
                                    parent = "/logs"
                                html_lines.append(f'<li><a href="{parent}">..</a></li>')
                            for item in sorted(items):
                                item_path = os.path.join(path.rstrip("/"), item)
                                html_lines.append(f'<li><a href="{item_path}">{item}</a></li>')
                            html_lines.append("</ul>")
                            content = "\n".join(html_lines)
                            content_type = "text/html"
                        except Exception as e:
                            content = f"500 Internal Server Error: {e}"
                            content_type = "text/plain"
                    else:
                        # File serving
                        try:
                            with open(target_path, "r", errors="ignore") as f:
                                content = f.read()
                            if target_path.suffix == ".json" or target_path.suffix == ".jsonl":
                                content_type = "application/json"
                            else:
                                content_type = "text/plain"
                        except Exception as e:
                            content = f"500 Internal Server Error: {e}"
                            content_type = "text/plain"
                else:
                    content = (
                        "Cyanide Honeypot Metrics Server. Use /metrics, /stats, /health or /logs."
                    )
                    content_type = "text/plain"

                payload = content.encode("utf-8", "ignore") if isinstance(content, str) else content

                response_header = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode()

                writer.write(response_header + payload)
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

    # Function 51: Retrieves host keys from disk or generates them if missing.
    def _get_host_keys(self) -> List[asyncssh.SSHKey]:
        """Load host keys from storage or generate persistent ones."""
        ssh_conf = self.config.get("ssh", {})
        data_dir = Path(ssh_conf.get("data_path", "var/lib/cyanide/keys"))
        data_dir.mkdir(parents=True, exist_ok=True)

        # Key types to support (Mimicry)
        key_types = ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"]
        loaded_keys = []

        for ktype in key_types:
            # Filename based on type (e.g., host_key_ssh-rsa)
            key_path = data_dir / f"host_key_{ktype}"

            if key_path.exists():
                try:
                    key = asyncssh.read_private_key(str(key_path))
                    loaded_keys.append(key)
                except Exception as e:
                    self.logger.log_event(
                        "system", "key_error", {"message": f"Failed to load {ktype}: {e}"}
                    )
            else:
                try:
                    self.logger.log_event(
                        "system",
                        "key_gen",
                        {"message": f"Generating new persistent {ktype} host key"},
                    )
                    key = asyncssh.generate_private_key(ktype)
                    key.write_private_key(str(key_path))
                    # Set permissions to 600
                    key_path.chmod(0o600)
                    loaded_keys.append(key)
                except Exception as e:
                    self.logger.log_event(
                        "system", "key_error", {"message": f"Failed to generate {ktype}: {e}"}
                    )

        if not loaded_keys:
            # Emergency fallback: generate a non-persistent RSA key
            return [asyncssh.generate_private_key("ssh-rsa")]

        return loaded_keys

    # Function 52: Performs operations related to start.
    async def start(self):
        """Start all honeypot services and enter main event loop."""
        # Start Async Logger
        await self.async_logger.start()

        # Load/Persistence SSH Host Keys
        host_keys = self._get_host_keys()

        # Initialize VM Pool if needed
        if self.config.get("pool", {}).get("enabled", False):
            self.logger.log_event("system", "service_starting", {"service": "vm_pool"})
            self.vm_pool = VMPool(self.config)
            
            try:
                self.background_tasks.append(asyncio.create_task(self.vm_pool.start()))
                self.logger.log_event("system", "service_started", {
                    "service": "vm_pool",
                    "mode": self.config.get("pool", {}).get("mode"),
                    "max_vms": self.config.get("pool", {}).get("max_vms")
                })
            except Exception as e:
                self.logger.log_event("system", "service_error", {"service": "vm_pool", "error": str(e)})
        else:
            self.vm_pool = VMPool(self.config) # Create dummy or disabled logic
            self.background_tasks.append(asyncio.create_task(self.vm_pool.start()))

        # Start SSH Server
        ssh_conf = self.config.get("ssh", {})
        ssh_enabled = ssh_conf.get("enabled", True)
        if ssh_enabled:
            ssh_port = ssh_conf["port"]
            backend_mode = ssh_conf.get("backend_mode", "emulated")  # emulated, proxy, pool

            if backend_mode == "emulated":
                # Anti-Fingerprinting
                # Use override from config if available, otherwise use banner from profile
                chosen_version = ssh_conf.get("version") or self.profile.get("ssh_banner", "")
                if chosen_version.startswith("SSH-2.0-"):
                    chosen_version = chosen_version[8:]

                self.logger.log_event(
                    "system", "system_status", {"message": f"SSH Banner: {chosen_version}"}
                )

                # Helper for rekey limit parsing
                def parse_rekey(limit: str) -> int:
                    if not limit:
                        return 1024**3  # 1G
                    limit = str(limit).upper()
                    if limit.endswith("G"):
                        return int(limit[:-1]) * 1024**3
                    if limit.endswith("M"):
                        return int(limit[:-1]) * 1024**2
                    if limit.endswith("K"):
                        return int(limit[:-1]) * 1024
                    return int(limit)

                # Build algorithm lists if configured
                ssh_opts = {
                    "server_host_keys": host_keys,
                    "server_factory": lambda: SSHServerFactory(self),
                    "reuse_address": True,
                    "server_version": chosen_version,
                    "encoding": None,  # Cyanide requires raw bytes for SCP/rsync
                    # Cyanide-grade security limits
                    "login_timeout": ssh_conf.get("login_timeout", 60),
                    "rekey_bytes": parse_rekey(ssh_conf.get("rekey_limit", "1G")),
                }

                if ssh_conf.get("sftp_enabled", True):
                    from cyanide.vfs.sftp import CyanideSFTPHandler
                    ssh_opts["sftp_factory"] = CyanideSFTPHandler

                # process_factory handles exec/shell requests (correct asyncssh API).
                # It receives an SSHServerProcess with .command, .stdin, .stdout, etc.
                honeypot_ref = self
                ssh_conf_ref = ssh_conf

                async def cyanide_process_factory(process):
                    """Route exec/shell to our honeypot handlers."""
                    import sys
                    import traceback
                    try:
                        conn = process.channel.get_connection()
                        # Retrieve the per-connection factory that SSHServerFactory stores
                        factory = getattr(conn, "cyanide_factory", None)
                        if factory is None:
                            process.exit(1)
                            return

                        command = process.command  # None for shell, str for exec
                        print(f"DEBUG process_factory: command={command!r} pid={id(process)}", flush=True)

                        if command is None:
                            # Shell request — delegate to SSHSession shell handler
                            sess = factory.sessions.get(factory.conn_id)
                            if sess:
                                sess.channel = process.channel
                                sess.session_started()
                                # Hand off stdin processing to SSHSession
                                async for data in process.stdin:
                                    sess.data_received(data, None)
                                sess.session_ended()
                            else:
                                process.exit(1)
                            return

                        # Log command
                        honeypot_ref.logger.log_event(
                            "conn_" + factory.conn_id,
                            "command.input",
                            {
                                "protocol": "ssh",
                                "src_ip": factory.src_ip,
                                "username": factory.username,
                                "input": command,
                                "client_version": factory.client_version,
                            },
                        )

                        # SCP interception
                        if command.startswith("scp ") and ssh_conf_ref.get("scp_enabled", True):
                            from cyanide.vfs.scp import SCPHandler
                            scp = SCPHandler(factory, process=process)
                            rc = await scp.handle(command)
                            process.exit(rc)
                            return

                        # rsync interception
                        if command.startswith("rsync ") and ssh_conf_ref.get("rsync_enabled", True):
                            from cyanide.vfs.rsync import RsyncHandler
                            rsync = RsyncHandler(factory, process=process)
                            rc = await rsync.handle(command)
                            process.exit(rc)
                            return

                        # Regular exec → ShellEmulator
                        fs = factory.fs or honeypot_ref.get_filesystem(factory.src_ip)

                        def q_hook(f, c):
                            honeypot_ref.save_quarantine_file(f, c, "conn_" + factory.conn_id, factory.src_ip)

                        shell = ShellEmulator(
                            fs,
                            factory.username,
                            quarantine_callback=q_hook,
                            config=honeypot_ref.config,
                        )
                        stdout, stderr, rc = await shell.execute(command)
                        print(f"DEBUG process_factory exec done rc={rc} out={stdout!r}", flush=True)
                        process.stdout.write(stdout.encode("utf-8") if isinstance(stdout, str) else stdout)
                        if stderr:
                            process.stderr.write(stderr.encode("utf-8") if isinstance(stderr, str) else stderr)
                        process.exit(rc)

                    except Exception as exc:
                        print(f"DEBUG process_factory EXCEPTION: {exc}", flush=True)
                        traceback.print_exc(file=sys.stdout)
                        sys.stdout.flush()
                        try:
                            process.exit(1)
                        except Exception:
                            pass

                ssh_opts["process_factory"] = cyanide_process_factory

                # Map user config keys to asyncssh.listen kwargs
                algo_map = {
                    "kex_algs": "kex_algs",
                    "ciphers": "encryption_algs",
                    "macs": "mac_algs",
                    "compression": "compression_algs",
                    "public_key_algs": "signature_algs",
                }
                actual_algs = {}
                for cfg_key, opt_key in algo_map.items():
                    val = ssh_conf.get(cfg_key)
                    if val:
                        ssh_opts[opt_key] = val
                        actual_algs[opt_key] = val

                self.ssh_server = await asyncssh.listen("0.0.0.0", ssh_port, **ssh_opts)
                self.logger.log_event(
                    "system", "service_started", {"service": "ssh_emulated", "port": ssh_port}
                )
                self.logger.log_event(
                    "system", "ssh_listen_started", {
                        "port": ssh_port,
                        "server_version": chosen_version,
                        "kex_algs": actual_algs.get("kex_algs"),
                        "encryption_algs": actual_algs.get("encryption_algs"),
                        "mac_algs": actual_algs.get("mac_algs"),
                        "compression_algs": actual_algs.get("compression_algs"),
                        "signature_algs": actual_algs.get("signature_algs")
                    }
                )
            elif backend_mode == "proxy" or backend_mode == "pool":
                # Use TCP Proxy for pure SSH monitoring (simplest approach for "Pure Proxy" request)
                # Or use the specific SSH Proxy implementation if we want to dissect packets?
                # The user asked for "pure telnet and ssh proxy with monitoring"
                # Our TCPProxy monitors data.
                # If pool, use selector.
                t_host = ssh_conf.get("target_host", "127.0.0.1")
                t_port = ssh_conf.get("target_port", 22)
                ssh_proxy = TCPProxy(
                    "0.0.0.0",
                    ssh_port,
                    target_host=t_host,
                    target_port=t_port,
                    protocol_name="ssh_proxy",
                    pool=self.vm_pool if backend_mode == "pool" else None,
                )
                await ssh_proxy.start()
                self.logger.log_event("system", "service_started", {"service": "ssh_proxy", "listen_port": ssh_port, "target": f"{t_host}:{t_port}"})

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
                t_host = telnet_conf.get("target_host", "127.0.0.1")
                t_port = int(telnet_conf.get("target_port", 2323))

                telnet_proxy = TCPProxy(
                    "0.0.0.0",
                    telnet_port,
                    target_host=t_host,
                    target_port=t_port,
                    protocol_name="telnet_proxy",
                    pool=self.vm_pool if backend_mode == "pool" else None,
                )
                await telnet_proxy.start()
                self.logger.log_event("system", "service_started", {"service": "telnet_proxy", "listen_port": telnet_port, "target": f"{t_host}:{t_port}"})

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
                self.logger.log_event("system", "service_started", {"service": "smtp_proxy", "listen_port": int(smtp_conf.get("listen_port", 25)), "target": f"{smtp_conf.get('target_host', '127.0.0.1')}:{smtp_conf.get('target_port', 2525)}"})
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

    # Function 53: Performs operations related to stop.
    async def stop(self):
        """Stop all services."""
        self.logger.log_event("system", "system_status", {"message": "Stopping CyanideServer..."})

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

    # Function 54: Handles event logging and telemetry.
    async def _stats_logging_loop(self):
        """Periodically log statistics to cyanide-stats.json."""
        self.logger.log_event("system", "service_started", {"service": "stats_loop", "interval_seconds": 60})
        while True:
            try:
                # Log current stats
                stats_data = self.stats.get_stats()
                self.logger.log_event("system", "stats", stats_data)
            except Exception as e:
                self.logger.log_event("system", "error", {"message": f"Stats Logging Error: {e}"})

            # Log every 60 seconds (or 10 for demo/dev if needed, but 60 is standard)
            await asyncio.sleep(60)

    # Function 55: Performs operations related to cleanup loop.
    async def _cleanup_loop(self):
        """Background task for automatic file cleanup."""
        # Initial delay to let things start
        await asyncio.sleep(60)

        from .cleanup import CleanupManager

        manager = CleanupManager(self.config, logger=self.logger)

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
        
        self.logger.log_event("system", "service_started", {"service": "cleanup_loop", "interval": manager.interval, "retention_days": manager.retention_days})

        while True:
            try:
                stats = manager.cleanup_files()
                if stats["deleted"] > 0:
                    self.logger.log_event(
                        "system",
                        "system_cleanup",
                        {
                            "deleted": stats["deleted"],
                            "bytes_freed": stats["bytes_freed"],
                        },
                    )
            except Exception as e:
                self.logger.log_event("system", "cleanup_error", {"message": f"Cleanup Error: {e}"})

            await asyncio.sleep(manager.interval)


class SSHServerFactory(asyncssh.SSHServer):
    """SSH server factory."""

    # Function 57: Initializes the class instance and its attributes.
    def __init__(self, honeypot: CyanideServer):
        super().__init__()
        self.honeypot = honeypot
        self.src_ip = "unknown"
        self.src_port = 0
        self.fs = None
        self.conn_id = str(uuid.uuid4())[:8]
        # Set max auth tries (Cyanide style)
        ssh_conf = self.honeypot.config.get("ssh", {})
        self._max_auth_tries = ssh_conf.get("auth_tries", 3)
        self.sessions = {}
        self.background_tasks = []
        self.username = "root"
        self.client_version = "unknown"

    # Function 58: Performs operations related to connection made.
    def connection_made(self, conn):
        self.conn = conn
        conn.cyanide_factory = self
        self.src_ip = conn.get_extra_info("peername")[0]
        self.src_port = conn.get_extra_info("peername")[1]
        
        # Initialize session filesystem
        self.fs = self.honeypot.get_filesystem(self.src_ip)

        self.client_version = conn.get_extra_info("client_version", "unknown")
        
        self.honeypot.logger.log_event(
            "conn_" + self.conn_id, "ssh_conn_open", {
                "src_ip": self.src_ip,
                "src_port": self.src_port
            }
        )

        # Negotiated algorithms are available after handshake,
        # but for now we log those that the transport already established.
        algos = conn.get_extra_info("algorithms") or {}

        self.honeypot.logger.log_event(
            "conn_" + self.conn_id,
            "ssh.connect",
            {
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "client_version": self.client_version,
                "kex_alg": algos.get("kex_algo"),
                "key_alg": algos.get("host_key_algo"),
                "cipher": algos.get("encryption_algo"),
                "mac": algos.get("mac_algo"),
                "compression": algos.get("compression_algo"),
            },
        )

        with self.honeypot.tracer.start_as_current_span("ssh_connection_setup") as span:
            span.set_attribute("net.peer.ip", self.src_ip)
            span.set_attribute("net.peer.port", self.src_port)

            # Check limits via SessionManager
            accepted, reason = self.honeypot.services.session.can_accept(self.src_ip)
            if not accepted:
                span.set_attribute("error", True)
                span.set_attribute("rejection_reason", reason)
                self.honeypot.logger.log_event(
                    "system", "connection_rejected", {
                        "protocol": "ssh",
                        "src_ip": self.src_ip, 
                        "reason": reason,
                        "active_sessions": self.honeypot.services.session.active_sessions,
                        "per_ip_sessions": self.honeypot.services.session.sessions_per_ip.get(self.src_ip, 0)
                    }
                )
                conn.close()
                return

            self.honeypot.services.session.register_session(self.src_ip, "ssh")

            # Create a filesystem instance for this connection with IP context
            self.fs = self.honeypot.get_filesystem(
                session_id="conn_" + self.conn_id, src_ip=self.src_ip
            )

    # Function 59: Performs operations related to connection lost.
    def connection_lost(self, exc):
        # Transport level cleanup - handle leaks here
        self.honeypot.services.session.unregister_session(self.src_ip)
        self.honeypot.logger.log_event(
            "conn_" + self.conn_id,
            "ssh_connection_lost",
            {
                "src_ip": self.src_ip,
                "active_sessions": self.honeypot.services.session.active_sessions,
            },
        )

    # Function 60: Performs operations related to password auth supported.
    def password_auth_supported(self):
        return True

    # Function 60.1: Performs operations related to publickey auth supported.
    def publickey_auth_supported(self):
        """Enable publickey auth to collect and log keys from attackers."""
        return True

    # Function 60.2: Validates publickey and logs it.
    def validate_publickey(self, username, key):
        """Log public key attempt and always fail to force password auth (Cyanide behavior)."""
        fingerprint = key.get_fingerprint()
        raw_key = key.export_public_key().decode()

        self.honeypot.logger.log_event(
            "conn_" + self.conn_id,
            "auth.publickey",
            {"username": username, "fingerprint": fingerprint, "key": raw_key, "success": False},
        )
        return False

    # Function 61: Performs operations related to validate password.
    def validate_password(self, username, password):
        self.username = username  # store for process_factory
        success = self.honeypot.is_valid_user(username, password)
        self.honeypot.stats.on_auth("ssh", self.src_ip, username, password, success)
        self.honeypot.logger.log_event(
            "conn_" + self.conn_id,
            "auth",
            {
                "protocol": "ssh",
                "src_ip": self.src_ip,
                "username": username,
                "password": password,
                "success": success,
            },
        )
        return success

    # Function 63: Performs operations related to session requested.
    def session_requested(self):
        print(f"DEBUG: session_requested for {self.src_ip}")
        sess = SSHSession(self.honeypot, self.fs, self.src_ip, self.src_port, self.conn_id)
        self.sessions[self.conn_id] = sess
        return sess

    # Function 62.1: Handles direct-tcpip requests (-L).
    def direct_tcpip_requested(self, dest_host, dest_port, src_host, src_port):
        self.honeypot.logger.log_event(
            "conn_" + self.conn_id,
            "local_forward.request",
            {
                "src_ip": self.src_ip,
                "dest_host": dest_host,
                "dest_port": dest_port,
                "src_host": src_host,
                "src_port": src_port,
            },
        )
        ssh_conf = self.honeypot.config.get("ssh", {})
        if not ssh_conf.get("forwarding_enabled", False):
            return False
        return True

    # Function 62.2: Handles remote port forwarding requests (-R).
    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):

        self.honeypot.logger.log_event(
            "conn_" + self.conn_id,
            "remote_forward.request",
            {
                "src_ip": self.src_ip,
                "dest_host": dest_host,
                "dest_port": dest_port,
            },
        )
        ssh_conf = self.honeypot.config.get("ssh", {})
        if not ssh_conf.get("forwarding_enabled", False):
            return False
        return True

    # Function 62.3: Implements actual port forwarding proxy logic.
    async def direct_tcpip(self, chan, dest_host, dest_port, src_host, src_port):
        ssh_conf = self.honeypot.config.get("ssh", {})
        target_host = dest_host
        target_port = dest_port
        mode = "allowed"

        # Policy Router
        port_str = str(dest_port)
        if ssh_conf.get("forward_redirect_enabled"):
            rules = ssh_conf.get("forward_redirect_rules", {})
            if port_str in rules:
                target_str = rules[port_str]
                if ":" in target_str:
                    target_host, p_str = target_str.split(":", 1)
                    target_port = int(p_str)
                else:
                    target_host = target_str
                mode = "redirect"

        if ssh_conf.get("forward_tunnel_enabled"):
            rules = ssh_conf.get("forward_tunnel_rules", {})
            if port_str in rules:
                target_str = rules[port_str]
                if ":" in target_str:
                    target_host, p_str = target_str.split(":", 1)
                    target_port = int(p_str)
                else:
                    target_host = target_str
                mode = "tunnel"

        self.honeypot.logger.log_event(
            "conn_" + self.conn_id,
            "forward.connect",
            {
                "src_ip": self.src_ip,
                "requested_host": dest_host,
                "requested_port": dest_port,
                "target_host": target_host,
                "target_port": target_port,
                "mode": mode,
            },
        )

        try:
            target_reader, target_writer = await asyncio.open_connection(target_host, target_port)

            async def chan_to_target():
                while not chan.at_eof():
                    try:
                        data = await chan.read()
                        if not data:
                            break
                        target_writer.write(data)
                        await target_writer.drain()
                    except Exception:
                        break
                target_writer.close()
                try:
                    await target_writer.wait_closed()
                except Exception:
                    pass

            async def target_to_chan():
                while True:
                    try:
                        data = await target_reader.read(4096)
                        if not data:
                            break
                        chan.write(data)
                        await chan.drain()
                    except Exception:
                        break
                chan.write_eof()

            await asyncio.gather(chan_to_target(), target_to_chan())
        except Exception as e:
            self.honeypot.logger.log_event(
                "conn_" + self.conn_id, "forward.error", {"message": f"Forward Error: {e}"}
            )
            chan.close()


class SSHSession(asyncssh.SSHServerSession):
    """SSH session handler."""

    # Function 64: Initializes the class instance and its attributes.
    def __init__(self, honeypot: CyanideServer, fs: FakeFilesystem, src_ip, src_port, conn_id: str):
        print(f"DEBUG: SSHSession.__init__ starting for {src_ip}")
        self.honeypot = honeypot
        self.fs = fs
        self.src_ip = src_ip
        self.src_port = src_port
        self.session_id = "conn_" + conn_id
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



    # Function 65: Performs operations related to connection made.
    def connection_made(self, channel):
        self.channel = channel
        conn = channel.get_connection()
        self.username = conn.get_extra_info("username") or "root"
        self.client_version = conn.get_extra_info("client_version") or "unknown"

        self.honeypot.stats.on_connect("ssh", self.src_ip)

        # GeoIP Lookup
        asyncio.create_task(self.honeypot.log_geoip(self.session_id, self.src_ip, "ssh"))

        # SSH Fingerprinting

        # SSH Fingerprinting
        # Extract negotiated algorithms (HASSH-like data)
        try:
            # Function 66: Retrieves val data.
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

            self.honeypot.logger.log_event(
                self.session_id,
                "client_fingerprint",
                {
                    "src_ip": self.src_ip,
                    "protocol": "ssh",
                    "fingerprint": fingerprint,
                    "client_version": self.client_version,
                },
            )
            
            self.honeypot.logger.log_event(
                self.session_id,
                "ssh_negotiated",
                {
                    "kex": kex,
                    "cipher_in": cipher,
                    "cipher_out": cipher,
                    "mac_in": mac,
                    "mac_out": mac,
                    "compression_in": compression,
                    "compression_out": compression,
                    "host_key_alg": key_algo,
                }
            )
        except Exception:
            pass

    # Function 67: Performs operations related to connection lost.
    def connection_lost(self, exc):
        """Log session disconnect."""
        reason = "clean"
        if exc:
            reason = f"error: {exc}"

        self.honeypot.stats.on_disconnect("ssh", self.src_ip)

        self.honeypot.logger.log_event(
            self.session_id,
            "session_disconnect",
            {
                "src_ip": self.src_ip,
                "reason": reason,
            },
        )

    # Function 68: Performs operations related to terminal size changed.
    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        """Log terminal resize events (SIGWINCH)."""
        self.honeypot.logger.log_event(
            self.session_id,
            "window_resize",
            {
                "src_ip": self.src_ip,
                "width": width,
                "height": height,
            },
        )
        if self.shell:
            # Propagate
            pass

    # Function 69: Performs operations related to shell requested.
    def shell_requested(self):
        # Function 70: Performs operations related to q hook.
        def q_hook(f, c):
            self.honeypot.save_quarantine_file(f, c, self.session_id, self.src_ip)

        self.shell = ShellEmulator(
            self.fs, self.username, quarantine_callback=q_hook, config=self.honeypot.config
        )
        return True

    # Function 71: Performs operations related to get prompt.
    def _get_prompt(self):
        if not self.shell:
            return "$ "
        if self.shell.pending_input_prompt:
            return self.shell.pending_input_prompt

        cwd = self.shell.cwd
        if cwd.startswith(f"/home/{self.username}"):
            cwd = cwd.replace(f"/home/{self.username}", "~", 1)
        elif self.username == "root" and cwd.startswith("/root"):
            cwd = cwd.replace("/root", "~", 1)
        return f"{self.username}@server:{cwd}$ "

    # Function 72: Performs operations related to session started.
    def session_started(self):
        self._ensure_tty_log()
        if self.shell:
            # self.channel.write(f"Welcome into {self.username} shell\r\n")
            self.channel.write(self._get_prompt())

    # Function 73: Handles event logging and telemetry.
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

    # Function 74: Handles event logging and telemetry.
    def _log_tty(self, direction: str, data: str):
        self.honeypot._log_tty(self, direction, data)

    # Function 75: Performs operations related to env received.
    def env_received(self, name, value):
        """Log client environment variables."""
        # Convert bytes to str if needed
        if isinstance(name, bytes):
            name = name.decode("utf-8", "ignore")
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")

        self.honeypot.logger.log_event(
            self.session_id,
            "client_env",
            {
                "src_ip": self.src_ip,
                "name": name,
                "value": value,
            },
        )
        return True

    # Function 76: Performs operations related to data received.
    def data_received(self, data, datatype=None):
        asyncio.create_task(self._process_input(data))

    # Function 77: Performs operations related to process input.
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
            self.honeypot.stats.on_traffic("in", len(data))

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
                    self.honeypot.logger.log_event(
                        self.session_id,
                        "ioc_detected",
                        {
                            "src_ip": self.src_ip,
                            "iocs": list(set(iocs)),
                            "cmd": cmd,
                        },
                    )

                self.honeypot.stats.on_command("ssh", self.src_ip, self.username, cmd)

                self.honeypot.logger.log_event(
                    self.session_id,
                    "command.input",
                    {
                        "protocol": "ssh",
                        "src_ip": self.src_ip,
                        "username": self.username,
                        "input": cmd,
                        "client_version": self.client_version,
                    },
                )

                # ML Analysis with bot detection
                if (
                    self.honeypot.services.analytics.ml_enabled
                    and self.honeypot.services.analytics.ml_pipeline
                ):
                    self.honeypot._analyze_command(
                        cmd, self.username, self.src_ip, self.session_id, "ssh", is_bot=is_bot
                    )

                if self.shell:
                    stdout, stderr, rc = await self.shell.execute(cmd)
                else:
                    stdout, stderr, rc = "", "Shell not initialized\n", 1

                # Confusion Metric
                if rc == 127:  # Command not found
                    self.honeypot.stats.on_command_not_found(cmd)
                    self.honeypot.logger.log_event(
                        self.session_id,
                        "command_not_found",
                        {
                            "src_ip": self.src_ip,
                            "cmd": cmd,
                        },
                    )

                response = stdout + stderr

                self.channel.write(response)
                self.bytes_out += len(response)
                self.honeypot.stats.on_traffic("out", len(response))
                self._log_tty("OUT", response)

                curr_prompt = self._get_prompt()
                self.channel.write(curr_prompt)
                self.bytes_out += len(curr_prompt)
                self.honeypot.stats.on_traffic("out", len(curr_prompt))
                self._log_tty("OUT", curr_prompt)
                self._log_tty("IN", cmd + "\n")

        except Exception as e:
            self.honeypot.logger.log_event(
                self.session_id, "debug", {"message": f"process_input error: {e}"}
            )

    # Function 78: Performs operations related to close session.
    async def _close_session(self):
        await asyncio.sleep(0.01)
        self.channel.write_eof()
        self.channel.exit(0)
        self.channel.close()

    # Function 79: Performs operations related to exec requested.
    def exec_requested(self, command):
        print(f"DEBUG exec_requested CALLED: {command!r}", flush=True)
        try:
            self.honeypot.logger.log_event(
                self.session_id, "debug", {"message": f"exec_requested: {command}"}
            )
            self.commands.append(command)
            self.honeypot.logger.log_event(
                self.session_id,
                "command.input",
                {
                    "protocol": "ssh",
                    "src_ip": self.src_ip,
                    "username": self.username,
                    "input": command,
                    "client_version": self.client_version,
                },
            )
        except Exception as e:
            print(f"DEBUG exec_requested LOGGING ERROR: {e}", flush=True)
            import traceback
            import sys
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()

        # SCP/rsync Interception
        ssh_conf = self.honeypot.config.get("ssh", {})
        try:
            if command.startswith("scp ") and ssh_conf.get("scp_enabled", True):
                scp = SCPHandler(self)
                asyncio.create_task(self._run_scp(scp, command))
                return True

            if command.startswith("rsync ") and ssh_conf.get("rsync_enabled", True):
                rsync = RsyncHandler(self)
                asyncio.create_task(self._run_rsync(rsync, command))
                return True
        except Exception as e:
            print(f"DEBUG exec_requested INTERCEPT ERROR: {e}", flush=True)
            import traceback
            import sys
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()

        print("DEBUG exec_requested creating _async_exec task", flush=True)
        asyncio.create_task(self._async_exec(command))
        return True

    # Function 79.1: Runs SCP handler and handles exit.
    async def _run_scp(self, scp, command):
        try:
            rc = await scp.handle(command)
            self.channel.exit(rc)
            self.channel.close()
        except Exception as e:
            self.honeypot.logger.log_event(
                self.session_id, "error", {"message": f"SCP handler crashed: {e}"}
            )
            traceback.print_exc()
            self.channel.exit(1)
            self.channel.close()

    # Function 79.2: Runs rsync handler and handles exit.
    async def _run_rsync(self, rsync, command):
        try:
            rc = await rsync.handle(command)
            self.channel.exit(rc)
            self.channel.close()
        except Exception as e:
            self.honeypot.logger.log_event(
                self.session_id, "error", {"message": f"Rsync handler crashed: {e}"}
            )
            traceback.print_exc()
            self.channel.exit(1)
            self.channel.close()

    # Function 80: Performs operations related to async exec.
    async def _async_exec(self, command):
        try:
            print(f"DEBUG _async_exec START: {command!r} fs={self.fs!r}", flush=True)
            # Use Factory
            self._ensure_tty_log()
            fs = self.fs
            if not fs:
                 fs = self.honeypot.get_filesystem(self.src_ip)

            def q_hook(f, c):
                self.honeypot.save_quarantine_file(f, c, self.session_id, self.src_ip)

            shell = ShellEmulator(
                fs,
                self.username,
                quarantine_callback=q_hook,
                config=self.honeypot.config,
            )
            print("DEBUG _async_exec shell created, executing...", flush=True)

            stdout, stderr, rc = await shell.execute(command)
            print(f"DEBUG _async_exec done rc={rc} stdout={stdout!r}", flush=True)

            self.channel.write(stdout)
            self.honeypot.stats.on_traffic("out", len(stdout))
            self._log_tty("OUT", stdout)

            if stderr:
                self.channel.write_stderr(stderr)
                self.honeypot.stats.on_traffic("out", len(stderr))
                self._log_tty("OUT", stderr)

            self.channel.write_eof()
            await asyncio.sleep(0.01)
            self.channel.exit(rc)
            self.channel.close()
            print("DEBUG _async_exec channel closed cleanly", flush=True)
        except Exception as e:
            print(f"DEBUG _async_exec EXCEPTION: {e}", flush=True)
            import sys
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            try:
                self.channel.exit(1)
                self.channel.close()
            except Exception:
                pass

    # Function 81: Performs operations related to session ended.
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

        self.honeypot.logger.log_event(
            self.session_id,
            "session_end",
            {
                "protocol": "ssh",
                "src_ip": self.src_ip,
                "username": self.username,
                "commands": self.commands,
                "duration": duration,
                "client_version": self.client_version,
                "keystroke_metrics": keystroke_stats,
                "traffic": {"bytes_in": self.bytes_in, "bytes_out": self.bytes_out},
            },
        )
