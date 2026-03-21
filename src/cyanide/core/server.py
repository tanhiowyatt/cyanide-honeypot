"""
Advanced SSH/Telnet Honeypot Server Implementation.
"""

import asyncio
import json
import logging
import secrets
import time
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import asyncssh

from cyanide import CyanideLogger
from cyanide.core.emulator import ShellEmulator
from cyanide.network.tcp_proxy import TCPProxy
from cyanide.services.analytics import AnalyticsService
from cyanide.services.quarantine import QuarantineService
from cyanide.services.session_manager import SessionManager
from cyanide.services.smtp_handler import SMTPHandler
from cyanide.services.telnet_handler import TelnetHandler
from cyanide.vfs.engine import FakeFilesystem
from cyanide.vfs.rsync import RsyncHandler
from cyanide.vfs.scp import ScpHandler

from .async_logger import AsyncLogger
from .config import _CONFIG_EVENTS
from .defaults import DEFAULT_METADATA
from .stats import StatsManager
from .telemetry import setup_telemetry
from .vm_pool import VMPool
from .vt_scanner import VTScanner

CONTENT_TYPE_PLAIN = "text/plain"
EVENT_COMMAND_INPUT = "command.input"


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

        try:
            log_dir = config.get("logging", {}).get("directory", "var/log/cyanide")
            logging_config = config.get("logging", {})
            self.logger = CyanideLogger(
                log_dir, config.get("output", {}), logging_config=logging_config
            )
            self.logger.log_event(
                "system", "service_init_status", {"message": "Logger initialized"}
            )

            for ev in _CONFIG_EVENTS:
                self.logger.log_event("system", ev["action"], ev["data"])

        except Exception as e:
            logging.error(f"[!] CyanideServer: Failed to initialize Logger: {e}")
            raise

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
            raise

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

        try:
            quarantine_svc = QuarantineService(config, self.logger)
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

        telnet_handler = TelnetHandler(self, config)

        self.services.telnet = telnet_handler

        self.ssh_server: Any = None
        self.telnet_server: Any = None
        self.smtp_server: Any = None
        self.metrics_server: Any = None
        self.background_tasks: List[asyncio.Task] = []

        self.async_logger = AsyncLogger()

        self.users = config.get("users", [])

        from .fs_utils import resolve_os_profile

        self.os_profile = resolve_os_profile(config.get("os_profile", "ubuntu"))
        self.vfs_root = config.get("vfs_root", "configs/profiles")

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

        self.vfs_persistence = config.get("ssh", {}).get("vfs_persistence", True)
        self.vfs_cache: Dict[str, FakeFilesystem] = {}

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
            self.services.analytics.analyze_command(cmd, src_ip, session_id, is_bot=is_bot)

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
                self.stats.on_honeytoken(str(path))

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

        if self.vfs_persistence and src_ip != "unknown" and src_ip in self.vfs_cache:
            return self.vfs_cache[src_ip]

        try:
            fs = FakeFilesystem(
                os_profile=self.os_profile,
                root_dir=self.vfs_root,
                audit_callback=audit_hook,
                stats=self.stats,
                users=self.users,
            )
            if src_ip != "unknown":
                self.vfs_cache[src_ip] = fs
            return fs
        except Exception as e:
            self.logger.log_event(
                session_id, "error", {"message": f"Error initializing new VFS: {e}"}
            )
            traceback.print_exc()
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
            if not hasattr(self, "_quarantine_tasks"):
                self._quarantine_tasks = set()
            task = asyncio.create_task(
                self.services.quarantine.save_file(filename, content, session_id, src_ip)
            )
            self._quarantine_tasks.add(task)
            task.add_done_callback(self._quarantine_tasks.discard)
        except RuntimeError:
            pass

    # Function 49: Handles event logging and telemetry.
    def _log_tty(self, session_obj, direction: str, data: str):
        """Dual format logging: JSONL for reading + Timing/TS for scriptreplay."""
        if direction != "OUT" and not hasattr(session_obj, "tty_log_path_jsonl"):
            return

        if hasattr(session_obj, "tty_log_path_jsonl"):
            try:
                now = time.time()
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

    def _get_health_status(self) -> str:
        ssh_up = self.ssh_server is not None
        telnet_up = self.telnet_server is not None
        smtp_up = self.smtp_server is not None or getattr(self, "smtp_proxy", None) is not None

        is_healthy = True
        if self.config.get("ssh", {}).get("enabled", True) and not ssh_up:
            is_healthy = False
        if self.config.get("telnet", {}).get("enabled", False) and not telnet_up:
            is_healthy = False
        if self.config.get("smtp", {}).get("enabled", False) and not smtp_up:
            is_healthy = False

        status_data = {
            "status": "healthy" if is_healthy else "unhealthy",
            "uptime": int(time.time() - self.stats.start_time),
            "services": {"ssh": ssh_up, "telnet": telnet_up, "smtp": smtp_up},
        }
        return json.dumps(status_data)

    def _route_metrics_request(self, path: str) -> tuple[str, str]:
        if path == "/metrics":
            return self.stats.to_prometheus(), f"{CONTENT_TYPE_PLAIN}; version=0.0.4; charset=utf-8"
        if path == "/stats":
            return json.dumps(self.stats.get_stats(), indent=2), "application/json"
        if path == "/health":
            return self._get_health_status(), "application/json"
        if path.startswith("/logs"):
            return "Log access is restricted in metrics mode.", CONTENT_TYPE_PLAIN
        return "Cyanide Metrics Server", CONTENT_TYPE_PLAIN

    async def _handle_metrics_request(self, reader, writer):
        try:
            try:
                header_data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3.0)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
                return
            if not header_data:
                return

            try:
                header_str = header_data.decode("utf-8", "ignore")
                parts = header_str.splitlines()[0].split()
                if len(parts) < 2:
                    return
                path = parts[1]
            except Exception:
                return

            content, content_type = self._route_metrics_request(path)

            payload = content.encode("utf-8", "ignore")
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + payload

            try:
                writer.write(response)
                await writer.drain()
                await asyncio.sleep(0.05)
            except Exception:
                pass
        except Exception as e:
            self.logger.log_event("system", "metrics_handler_error", {"error": str(e)})
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # Function 50: Performs operations related to start metrics server.
    async def start_metrics_server(self):
        """Start a lightweight HTTP server for metrics and stats."""
        metrics_conf = self.config.get("metrics", {})
        if not metrics_conf.get("enabled", True):
            return

        port = metrics_conf.get("port", 9090)

        try:
            self.metrics_server = await asyncio.start_server(
                self._handle_metrics_request, "0.0.0.0", port
            )
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

        key_types = ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"]
        loaded_keys = []

        for ktype in key_types:
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
                    key_path.chmod(0o600)
                    loaded_keys.append(key)
                except Exception as e:
                    self.logger.log_event(
                        "system", "key_error", {"message": f"Failed to generate {ktype}: {e}"}
                    )

        if not loaded_keys:
            return [asyncssh.generate_private_key("ssh-rsa")]

        return loaded_keys

    def _start_vm_pool(self):
        if self.config.get("pool", {}).get("enabled", False):
            self.logger.log_event("system", "service_starting", {"service": "vm_pool"})
            self.vm_pool = VMPool(self.config, logger=self.logger)

            try:
                self.background_tasks.append(asyncio.create_task(self.vm_pool.start()))
                self.logger.log_event(
                    "system",
                    "service_started",
                    {
                        "service": "vm_pool",
                        "mode": self.config.get("pool", {}).get("mode"),
                        "max_vms": self.config.get("pool", {}).get("max_vms"),
                    },
                )
            except Exception as e:
                self.logger.log_event(
                    "system", "service_error", {"service": "vm_pool", "error": str(e)}
                )
        else:
            self.vm_pool = VMPool(self.config, logger=self.logger)
            self.background_tasks.append(asyncio.create_task(self.vm_pool.start()))

    @staticmethod
    def _parse_ssh_rekey(limit: str) -> int:
        if not limit:
            return 1024**3
        limit = str(limit).upper()
        if limit.endswith("G"):
            return int(limit[:-1]) * 1024**3
        if limit.endswith("M"):
            return int(limit[:-1]) * 1024**2
        if limit.endswith("K"):
            return int(limit[:-1]) * 1024
        return int(limit)

    @staticmethod
    async def _handle_shell_session(process, sess):
        """Handle interactive shell session loop."""
        if not sess.shell:
            sess.shell_requested()

        sess.session_started()
        await process.stdout.drain()

        async for data in process.stdin:
            try:
                sess.data_received(data, None)
                await process.stdout.drain()
            except (
                asyncssh.TerminalSizeChanged,
                asyncssh.BreakReceived,
                asyncssh.SignalReceived,
            ):
                continue
            except Exception as e:
                print(f"DEBUG: CyanideProcess stdin loop error: {e}", flush=True)
                break

        sess.session_ended()

    @staticmethod
    async def _handle_exec_session(process, sess, factory, command):
        """Handle non-interactive EXEC session."""
        ssh_conf = factory.honeypot.config.get("ssh", {})
        if command.startswith("rsync ") and ssh_conf.get("rsync_enabled", True):
            rsync = RsyncHandler(sess, process)
            rc = await rsync.handle(command)
            process.exit(rc)
            return

        if (command.startswith("scp ") or command.startswith("/usr/bin/scp ")) and ssh_conf.get(
            "scp_enabled", True
        ):
            scp = ScpHandler(sess, process)
            rc = await scp.handle(command)
            process.exit(rc)
            return

        await sess._async_exec(command)

    @staticmethod
    async def _cyanide_ssh_process_factory(process):
        """Expert AsyncSSH process factory handling shell and exec."""
        try:
            command = process.command
            conn = process.channel.get_connection()
            factory = getattr(conn, "cyanide_factory", None)

            if not factory:
                process.exit(1)
                return

            sess = factory.sessions.get(factory.conn_id)
            if not sess:
                sess = factory.session_requested()

            if not sess:
                process.exit(1)
                return

            sess.process = process
            sess.channel = process.channel

            if not command:
                await CyanideServer._handle_shell_session(process, sess)
            else:
                await CyanideServer._handle_exec_session(process, sess, factory, command)
        except Exception as e:
            print(f"DEBUG: CyanideProcess EXCEPTION: {e}", flush=True)
            traceback.print_exc()
            process.exit(1)

    def _get_ssh_options(self, ssh_conf, host_keys):
        """Prepare SSH options for the server."""
        chosen_version = ssh_conf.get("version") or self.profile.get("ssh_banner", "")
        if chosen_version.startswith("SSH-2.0-"):
            chosen_version = chosen_version[8:]

        self.logger.log_event(
            "system", "system_status", {"message": f"SSH Banner: {chosen_version}"}
        )

        ssh_opts = {
            "server_host_keys": host_keys,
            "server_factory": lambda: SSHServerFactory(self),
            "reuse_address": True,
            "server_version": chosen_version,
            "process_factory": self._cyanide_ssh_process_factory,
            "encoding": "utf-8",
            "login_timeout": ssh_conf.get("login_timeout", 60),
            "rekey_bytes": self._parse_ssh_rekey(ssh_conf.get("rekey_limit", "1G")),
        }

        if ssh_conf.get("sftp_enabled", True):
            from cyanide.vfs.sftp import CyanideSFTPHandler

            ssh_opts["sftp_factory"] = CyanideSFTPHandler

        ssh_opts["allow_scp"] = False

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

        return ssh_opts, chosen_version, actual_algs

    async def _start_ssh_service(self, host_keys):
        ssh_conf = self.config.get("ssh", {})
        ssh_enabled = ssh_conf.get("enabled", True)
        if not ssh_enabled:
            return

        ssh_port = ssh_conf["port"]
        backend_mode = ssh_conf.get("backend_mode", "emulated")

        if backend_mode == "emulated":
            ssh_opts, chosen_version, actual_algs = self._get_ssh_options(ssh_conf, host_keys)
            self.ssh_server = await asyncssh.listen("0.0.0.0", ssh_port, **ssh_opts)
            self.logger.log_event(
                "system", "service_started", {"service": "ssh_emulated", "port": ssh_port}
            )
            self.logger.log_event(
                "system",
                "ssh_listen_started",
                {
                    "port": ssh_port,
                    "server_version": chosen_version,
                    "kex_algs": actual_algs.get("kex_algs"),
                    "encryption_algs": actual_algs.get("encryption_algs"),
                    "mac_algs": actual_algs.get("mac_algs"),
                    "compression_algs": actual_algs.get("compression_algs"),
                    "signature_algs": actual_algs.get("signature_algs"),
                },
            )
        elif backend_mode == "proxy" or backend_mode == "pool":
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
            self.logger.log_event(
                "system",
                "service_started",
                {
                    "service": "ssh_proxy",
                    "listen_port": ssh_port,
                    "target": f"{t_host}:{t_port}",
                },
            )

    async def _start_telnet_service(self):
        telnet_conf = self.config.get("telnet", {})
        if not telnet_conf.get("enabled", False):
            return

        telnet_port = telnet_conf["port"]
        backend_mode = telnet_conf.get("backend_mode", "emulated")

        if backend_mode == "emulated":
            self.telnet_server = await asyncio.start_server(
                self.services.telnet.handle_connection, "0.0.0.0", telnet_port, reuse_address=True
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
            self.logger.log_event(
                "system",
                "service_started",
                {
                    "service": "telnet_proxy",
                    "listen_port": telnet_port,
                    "target": f"{t_host}:{t_port}",
                },
            )

    async def _start_smtp_service(self):
        smtp_conf = self.config.get("smtp", {})
        if not smtp_conf.get("enabled", False):
            return

        smtp_port = int(smtp_conf.get("port", 25))
        backend_mode = smtp_conf.get("backend_mode", "emulated")

        try:
            if backend_mode == "emulated":
                smtp_handler = SMTPHandler(self, smtp_conf)
                self.smtp_server = await asyncio.start_server(
                    smtp_handler.handle_connection, "0.0.0.0", smtp_port, reuse_address=True
                )
                self.logger.log_event(
                    "system", "service_started", {"service": "smtp_emulated", "port": smtp_port}
                )
            else:
                self.smtp_server = TCPProxy(
                    "0.0.0.0",
                    smtp_port,
                    smtp_conf.get("target_host", "127.0.0.1"),
                    int(smtp_conf.get("target_port", 25255)),
                    protocol_name="smtp",
                )
                await self.smtp_server.start()
                self.logger.log_event(
                    "system",
                    "service_started",
                    {
                        "service": "smtp_proxy",
                        "port": smtp_port,
                        "target": f"{smtp_conf.get('target_host', '127.0.0.1')}:{smtp_conf.get('target_port', 25255)}",
                    },
                )
        except Exception as e:
            self.logger.log_event(
                "system", "smtp_error", {"message": f"Failed to start SMTP Service: {e}"}
            )

    # Function 52: Performs operations related to start.
    async def start(self):
        """Start all honeypot services and enter main event loop."""
        self.async_logger.start()

        host_keys = self._get_host_keys()

        self._start_vm_pool()

        await self._start_ssh_service(host_keys)
        await self._start_telnet_service()
        await self._start_smtp_service()

        self.background_tasks.append(asyncio.create_task(self.start_metrics_server()))
        self.background_tasks.append(asyncio.create_task(self._cleanup_loop()))
        self.background_tasks.append(asyncio.create_task(self._stats_logging_loop()))

        try:
            self._stop_event = asyncio.Event()
            await self._stop_event.wait()
        except asyncio.CancelledError:
            await self.stop()
            raise

    # Function 53: Performs operations related to stop.
    async def stop(self):
        """Stop all services."""
        self.logger.log_event("system", "system_status", {"message": "Stopping CyanideServer..."})

        for task in self.background_tasks:
            task.cancel()

        if self.ssh_server:
            self.ssh_server.close()
            await self.ssh_server.wait_closed()
        if self.telnet_server:
            self.telnet_server.close()
            await self.telnet_server.wait_closed()
        if self.smtp_server:
            self.smtp_server.close()
            await self.smtp_server.wait_closed()
        if self.metrics_server:
            self.metrics_server.close()
            await self.metrics_server.wait_closed()

        await self.async_logger.stop()

        if hasattr(self, "_stop_event"):
            self._stop_event.set()

    # Function 54: Handles event logging and telemetry.
    async def _stats_logging_loop(self):
        """Periodically log statistics to cyanide-stats.json."""
        self.logger.log_event(
            "system", "service_started", {"service": "stats_loop", "interval_seconds": 60}
        )
        while True:
            try:
                stats_data = self.stats.get_stats()
                self.logger.log_event("system", "stats", stats_data)
            except Exception as e:
                self.logger.log_event("system", "error", {"message": f"Stats Logging Error: {e}"})

            await asyncio.sleep(60)

    # Function 55: Performs operations related to cleanup loop.
    async def _cleanup_loop(self):
        """Background task for automatic file cleanup."""
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

        self.logger.log_event(
            "system",
            "service_started",
            {
                "service": "cleanup_loop",
                "interval": manager.interval,
                "retention_days": manager.retention_days,
            },
        )

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
        ssh_conf = self.honeypot.config.get("ssh", {})
        self._max_auth_tries = ssh_conf.get("auth_tries", 3)
        self.sessions: dict[str, Any] = {}
        self._background_tasks: set[asyncio.Task] = set()
        self.username = "root"
        self.client_version = "unknown"

    # Function 58: Performs operations related to connection made.
    def connection_made(self, conn):
        self.conn = conn
        conn.cyanide_factory = self
        self.src_ip = conn.get_extra_info("peername")[0]
        self.src_port = conn.get_extra_info("peername")[1]
        self.client_version = conn.get_extra_info("client_version", "unknown")

        algos = conn.get_extra_info("algorithms") or {}
        self._log_connection_details(conn, algos)

        if not self._check_session_limits(conn):
            return

        self.honeypot.services.session.register_session(self.src_ip)

        self.fs = self.honeypot.get_filesystem(
            session_id="conn_" + self.conn_id, src_ip=self.src_ip
        )

    def _log_connection_details(self, conn, algos):
        """Log connection opening and algorithms."""
        self.honeypot.logger.log_event(
            "conn_" + self.conn_id,
            "ssh_conn_open",
            {"src_ip": self.src_ip, "src_port": self.src_port},
        )

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

    def _check_session_limits(self, conn):
        """Check if connection can be accepted based on session limits."""
        with self.honeypot.tracer.start_as_current_span("ssh_connection_setup") as span:
            span.set_attribute("net.peer.ip", self.src_ip)
            span.set_attribute("net.peer.port", self.src_port)

            accepted, reason = self.honeypot.services.session.can_accept(self.src_ip)
            if not accepted:
                span.set_attribute("error", True)
                span.set_attribute("rejection_reason", reason)
                self.honeypot.logger.log_event(
                    "system",
                    "connection_rejected",
                    {
                        "protocol": "ssh",
                        "src_ip": self.src_ip,
                        "reason": reason,
                        "active_sessions": self.honeypot.services.session.active_sessions,
                        "per_ip_sessions": self.honeypot.services.session.sessions_per_ip.get(
                            self.src_ip, 0
                        ),
                    },
                )
                conn.close()
                return False
            return True

    # Function 59: Performs operations related to connection lost.
    def connection_lost(self, exc):
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
    async def validate_password(self, username, password):
        self.username = username
        success = self.honeypot.is_valid_user(username, password)
        self.honeypot.stats.on_auth(username, password, success)
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

        if success:
            ssh_conf = self.honeypot.config.get("ssh", {})
            auth_delay = ssh_conf.get("auth_delay", 1.0)
            if auth_delay > 0:
                await asyncio.sleep(auth_delay)

        return success

    # Function 63: Performs operations related to session requested.
    def session_requested(self):
        print(f"DEBUG: session_requested for {self.src_ip}", flush=True)
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
        target_host, target_port, mode = self._get_forward_target(dest_host, dest_port)

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
            await self._bridge_tcpip(chan, target_host, target_port)
        except Exception as e:
            self.honeypot.logger.log_event(
                "conn_" + self.conn_id, "forward.error", {"message": f"Forward Error: {e}"}
            )
            chan.close()

    def _get_forward_target(self, dest_host, dest_port):
        """Apply redirect and tunnel rules to get the actual target."""
        ssh_conf = self.honeypot.config.get("ssh", {})
        target_host = dest_host
        target_port = dest_port
        mode = "allowed"
        port_str = str(dest_port)

        for rule_type in ["forward_redirect", "forward_tunnel"]:
            if ssh_conf.get(f"{rule_type}_enabled"):
                rules = ssh_conf.get(f"{rule_type}_rules", {})
                if port_str in rules:
                    target_str = rules[port_str]
                    if ":" in target_str:
                        target_host, p_str = target_str.split(":", 1)
                        target_port = int(p_str)
                    else:
                        target_host = target_str
                    mode = rule_type.split("_")[1]
                    break
        return target_host, target_port, mode

    async def _forward_stream(self, reader, writer, close_writer: bool = True):
        """Generic stream forwarding from reader to writer."""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            if close_writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            else:
                try:
                    writer.write_eof()
                except Exception:
                    pass

    async def _bridge_tcpip(self, chan, target_host, target_port):
        """Bridge the SSH channel and the target TCP connection."""
        target_reader, target_writer = await asyncio.open_connection(target_host, target_port)

        await asyncio.gather(
            self._forward_stream(chan, target_writer, close_writer=True),
            self._forward_stream(target_reader, chan, close_writer=False),
        )


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
        self.keystrokes: List[float] = []
        self.bytes_in = 0
        self.bytes_out = 0
        self.process: Optional[asyncssh.SSHServerProcess] = None
        self._background_tasks: set[asyncio.Task] = set()

    # Function 65: Performs operations related to connection made.
    def connection_made(self, channel):
        super().connection_made(channel)
        self.channel = channel
        conn = channel.get_connection()
        factory = getattr(conn, "cyanide_factory", None)
        self.username = factory.username if factory else (conn.get_extra_info("username") or "root")
        self.client_version = conn.get_extra_info("client_version") or "unknown"

        self.honeypot.stats.on_connect("ssh", self.src_ip)

        task = asyncio.create_task(self.honeypot.log_geoip(self.session_id, self.src_ip, "ssh"))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        try:
            self._log_ssh_details(conn)
        except Exception:
            pass

    def _get_ssh_info(self, conn, key, internal_attr=None, decode=False):
        """Helper to get SSH connection info with fallback."""
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

    def _log_ssh_details(self, conn):
        """Extract and log SSH fingerprint and negotiated algorithms."""
        kex = self._get_ssh_info(conn, "kex")
        key_algo = self._get_ssh_info(conn, "server_host_key")

        cipher = self._get_ssh_info(conn, "cipher", "_encryption_algo", True)
        mac = self._get_ssh_info(conn, "mac", "_mac_algo", True)
        compression = self._get_ssh_info(conn, "compression", "_compression_algo", True)

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
            },
        )

    # Function 67: Performs operations related to connection lost.
    def connection_lost(self, exc):
        """Log session disconnect."""
        reason = "clean"
        if exc:
            reason = f"error: {exc}"

        self.honeypot.stats.on_disconnect()

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

    # Function 69: Performs operations related to shell requested.
    def shell_requested(self):
        print(f"DEBUG: shell_requested called for {self.src_ip}", flush=True)

        # Function 70: Performs operations related to q hook.
        def q_hook(f, c):
            self.honeypot.save_quarantine_file(f, c, self.session_id, self.src_ip)

        self.shell = ShellEmulator(
            self.fs,
            self.username,
            quarantine_callback=q_hook,
            config=self.honeypot.config,
            logger=self.honeypot.logger,
            session_id=self.session_id,
            src_ip=self.src_ip,
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
            banner = (
                "\r\n"
                "Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-41-generic x86_64)\r\n"
                "\r\n"
                " * Documentation:  https://help.ubuntu.com\r\n"
                " * Management:     https://landscape.canonical.com\r\n"
                " * Support:        https://ubuntu.com/advantage\r\n"
                "\r\n"
                "Last login: Fri Mar 13 14:20:01 2026 from 192.168.1.10\r\n"
            )
            self._write(banner)
            prompt = self._get_prompt()
            self._write(prompt)

    # Function 72.1: Unified write method for SSH/Telnet.
    def _write(self, data):
        """Helper to write to channel/process and log."""
        if not data:
            return

        if hasattr(self, "process") and self.process and hasattr(self.process, "stdout"):
            if isinstance(data, bytes):
                data = data.decode("utf-8", "ignore")
            self.process.stdout.write(data)
        else:
            if isinstance(data, str):
                encoded = data.encode("utf-8")
            else:
                encoded = data
            self.channel.write(encoded)

        self._log_tty("OUT", data)

    # Function 73: Handles event logging and telemetry.
    def _ensure_tty_log(self):
        folder_name = f"ssh_{self.src_ip}_{self.session_id}"
        log_dir = Path(self.honeypot.logger.log_dir) / "tty" / folder_name
        log_dir.mkdir(parents=True, exist_ok=True)

        self.tty_log_path_jsonl = log_dir / f"{folder_name}.jsonl"
        self.tty_log_path = log_dir / f"{folder_name}.log"
        self.tty_timing_path = log_dir / f"{folder_name}.time"
        self.last_log_time = time.time()

        open(self.tty_log_path_jsonl, "a").close()
        open(self.tty_log_path, "a").close()
        open(self.tty_timing_path, "a").close()

    # Function 74: Handles event logging and telemetry.
    def _log_tty(self, direction: str, data: str):
        self.honeypot._log_tty(self, direction, data)

    # Function 75: Performs operations related to env received.
    def env_received(self, name, value):
        """Log client environment variables."""
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
        task = asyncio.create_task(self._process_input(data))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    # Function 77: Performs operations related to process input.
    async def _process_input(self, data):
        try:
            if isinstance(data, bytes):
                data = data.decode("utf-8", errors="ignore")

            is_paste = len(data) > 1 and ("\n" in data or "\r" in data)

            now = time.time()
            self.keystrokes.append(now)

            rng = secrets.SystemRandom()
            delay = rng.uniform(0.5, 1.5) if rng.random() < 0.1 else rng.uniform(0.02, 0.15)
            await asyncio.sleep(delay)

            self.bytes_in += len(data)
            self.honeypot.stats.on_traffic("in", len(data))

            self._log_tty("IN", data)
            self.buf += data

            while "\n" in self.buf or "\r" in self.buf:
                if "\n" in self.buf:
                    line, self.buf = self.buf.split("\n", 1)
                else:
                    line, self.buf = self.buf.split("\r", 1)

                cmd = line.strip()
                if not cmd:
                    self._write("\r\n" + self._get_prompt())
                    continue

                is_bot = self._calculate_is_bot(is_paste)
                self.keystrokes = []

                if self._handle_system_commands(cmd):
                    return

                self._detect_iocs(cmd)
                await self._execute_shell_command(cmd, is_bot)

        except Exception as e:
            self.honeypot.logger.log_event(
                self.session_id, "debug", {"message": f"process_input error: {e}"}
            )

    def _calculate_is_bot(self, is_paste):
        """Determine if input resembles a bot."""
        if is_paste:
            return True
        if len(self.keystrokes) > 1:
            delays = [
                self.keystrokes[i] - self.keystrokes[i - 1] for i in range(1, len(self.keystrokes))
            ]
            if delays and (sum(delays) / len(delays)) < 0.01:
                return True
        return False

    def _handle_system_commands(self, cmd):
        """Handle logout/exit commands."""
        if cmd in ("exit", "logout"):
            task = asyncio.create_task(self._close_session())
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
            return True
        return False

    def _detect_iocs(self, cmd):
        """Scan command for Indicators of Compromise."""
        import re

        ipv4_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        urls_regex = (
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
        )

        iocs = list(set(re.findall(ipv4_regex, cmd) + re.findall(urls_regex, cmd)))
        if iocs:
            self.honeypot.logger.log_event(
                self.session_id,
                "ioc_detected",
                {"src_ip": self.src_ip, "iocs": iocs, "cmd": cmd},
            )

    async def _execute_shell_command(self, cmd, is_bot):
        """Log and execute the shell command."""
        self.commands.append(cmd)
        self.honeypot.stats.on_command("ssh", self.src_ip, self.username, cmd)

        self.honeypot.logger.log_event(
            self.session_id,
            EVENT_COMMAND_INPUT,
            {
                "protocol": "ssh",
                "src_ip": self.src_ip,
                "username": self.username,
                "input": cmd,
                "client_version": self.client_version,
            },
        )

        if self.honeypot.services.analytics.ml_enabled:
            self.honeypot._analyze_command(
                cmd, self.username, self.src_ip, self.session_id, "ssh", is_bot=is_bot
            )

        try:
            if self.shell:
                stdout, stderr, rc = await self.shell.execute(cmd)
            else:
                stdout, stderr, rc = "", "Shell not initialized\n", 1
        except SystemExit as se:  # noqa: S5754
            # We must not re-raise SystemExit to prevent a malicious user from
            # crashing the server with a command like "mkdir --help" or argparse usage.
            rc = se.code if isinstance(se.code, int) else 2
            stdout, stderr = "", f"{cmd.split()[0] if cmd else 'shell'}: argument error\n"

        if rc == 127:
            self.honeypot.stats.on_command_not_found(cmd)
            self.honeypot.logger.log_event(
                self.session_id, "command_not_found", {"src_ip": self.src_ip, "cmd": cmd}
            )

        response = stdout + stderr
        self._write(response)
        self.bytes_out += len(response)
        self.honeypot.stats.on_traffic("out", len(response))

        prompt = self._get_prompt()
        self._write(prompt)
        self.bytes_out += len(prompt)
        self.honeypot.stats.on_traffic("out", len(prompt))
        self._log_tty("IN", cmd + "\n")

    # Function 78: Performs operations related to close session.
    async def _close_session(self):
        await asyncio.sleep(0.01)
        self.channel.write_eof()
        self.channel.exit(0)
        self.channel.close()

    # Function 79: Performs operations related to exec requested.
    def exec_requested(self, command):
        if not command or not command.strip():
            return False

        self.commands.append(command)
        self.honeypot.logger.log_event(
            self.session_id,
            EVENT_COMMAND_INPUT,
            {
                "protocol": "ssh",
                "src_ip": self.src_ip,
                "username": self.username,
                "input": command,
                "client_version": self.client_version,
            },
        )

        if self.honeypot.services.analytics.ml_enabled:
            self.honeypot._analyze_command(
                command, self.username, self.src_ip, self.session_id, "ssh"
            )

        task = asyncio.create_task(self._async_exec(command))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return True

    # Function 80: Performs operations related to async exec.
    async def _async_exec(self, command):
        try:
            self._ensure_tty_log()

            def q_hook(f, c):
                self.honeypot.save_quarantine_file(f, c, self.session_id, self.src_ip)

            shell = ShellEmulator(
                self.fs or self.honeypot.get_filesystem(self.session_id, self.src_ip),
                self.username,
                quarantine_callback=q_hook,
                config=self.honeypot.config,
                logger=self.honeypot.logger,
                session_id=self.session_id,
                src_ip=self.src_ip,
            )

            try:
                stdout, stderr, rc = await shell.execute(command)
            except SystemExit as se:  # noqa: S5754
                # We must not re-raise SystemExit to prevent a malicious user from
                # crashing the server with a command like "mkdir --help" or argparse usage.
                rc = se.code if isinstance(se.code, int) else 2
                stdout, stderr = (
                    "",
                    f"{command.split()[0] if command else 'shell'}: argument error\n",
                )

            self._write_exec_output(stdout, stderr, rc)

        except Exception as e:
            self.honeypot.logger.log_event(
                self.session_id, "error", {"message": f"Exec error: {e}"}
            )
            try:
                self.channel.exit(1)
                self.channel.close()
            except Exception:
                pass

    def _write_exec_output(self, stdout, stderr, rc):
        """Helper to write process/channel output and exit."""
        if self.process:
            self._write_to_process(stdout, stderr, rc)
        else:
            self._write_to_channel(stdout, stderr, rc)

        self._log_tty("OUT", stdout)
        if stderr:
            self._log_tty("OUT", stderr)

    def _write_to_process(self, stdout, stderr, rc):
        if not self.process:
            return
        stdout_str = stdout.decode("utf-8", "ignore") if isinstance(stdout, bytes) else stdout
        self.process.stdout.write(stdout_str)
        if stderr:
            stderr_str = stderr.decode("utf-8", "ignore") if isinstance(stderr, bytes) else stderr
            self.process.stderr.write(stderr_str)
        self.process.exit(rc)

    def _write_to_channel(self, stdout, stderr, rc):
        self.channel.write(stdout.encode() if isinstance(stdout, str) else stdout)
        if stderr:
            self.channel.write_stderr(stderr.encode() if isinstance(stderr, str) else stderr)
        self.channel.write_eof()
        self.channel.exit(rc)
        self.channel.close()

    # Function 81: Performs operations related to session ended.
    def session_ended(self):
        duration = time.time() - self.start_time

        keystroke_stats = {}
        if len(self.keystrokes) > 1:
            diffs = []
            for i in range(1, len(self.keystrokes)):
                diffs.append(self.keystrokes[i] - self.keystrokes[i - 1])

            avg = sum(diffs) / len(diffs)

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
