import asyncio
import hashlib
import random
import time
import traceback
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class TelnetHandler:
    """
    Handles Telnet connections and interactive shell emulation.
    """

    LOGIN_PROMPT = b"login: "
    PASSWORD_PROMPT = b"Password: "

    def __init__(self, server, config: Dict):
        self.server = server
        self.config = config
        self.logger = server.logger
        self.services = server.services
        self.stats = server.stats
        self.session_timeout = config.get("session_timeout", 300)

    async def handle_connection(self, reader, writer):
        """Handle Telnet connection."""
        src_ip, src_port = writer.get_extra_info("peername")
        session_id, tty_state, success = await self._prepare_session(src_ip, writer)
        if not success:
            return

        start_time = time.time()
        bytes_in, bytes_out = 0, 0
        username = ""
        commands: List[str] = []

        try:

            self.logger.log_event(
                session_id,
                "connect",
                {"protocol": "telnet", "src_ip": src_ip, "src_port": src_port},
            )
            geoip_task = asyncio.create_task(self.services.analytics.log_geoip(src_ip))
            self.stats.on_connect("telnet", src_ip)

            fs = self.server.get_filesystem(session_id, src_ip)
            bytes_out += await self._send_banner(writer, fs)

            auth_success, username, b_in, b_out = await self._perform_auth(
                reader, writer, session_id, src_ip
            )
            bytes_in += b_in
            bytes_out += b_out

            if auth_success:
                # Re-fetch VFS now that we have a verified username
                fs = self.server.get_filesystem(session_id, src_ip, username=username)

                from cyanide.core.emulator import ShellEmulator

                self.logger.log_event(
                    session_id,
                    "session.start",
                    {"protocol": "telnet", "src_ip": src_ip, "session_id": session_id},
                )
                shell = ShellEmulator(
                    fs,
                    username,
                    quarantine_callback=lambda f, c: self.services.quarantine.save_file(
                        f,
                        c,
                        session_id,
                        src_ip,
                        sub_dir=f"telnet_{src_ip}_{session_id}",
                    ),
                    config=self.config,
                    logger=self.logger,
                    session_id=session_id,
                    src_ip=src_ip,
                )
                b_in, b_out, cmds = await self._run_shell(
                    reader, writer, shell, tty_state, session_id, src_ip, username
                )
                bytes_in += b_in
                bytes_out += b_out
                commands.extend(cmds)

            await geoip_task
        except Exception as e:
            self.logger.log_event(
                "system",
                "telnet_error",
                {"src_ip": src_ip, "message": f"Telnet Connection Error: {e}"},
            )
            self.logger.log_event(
                session_id, "telnet_exception", {"traceback": traceback.format_exc()}
            )
        finally:
            if "fs" in locals():
                fs.save_ip_history()
            await self._cleanup_session(
                writer,
                session_id,
                src_ip,
                username,
                start_time,
                commands,
                bytes_in,
                bytes_out,
            )

    async def _prepare_session(self, src_ip: str, writer) -> Tuple[str, Optional[object], bool]:
        """Check session limits, register session, and prepare log directory."""
        await asyncio.sleep(0)
        accepted, reason = self.services.session.can_accept(src_ip)
        if not accepted:
            self.logger.log_event(
                "system",
                "connection_rejected",
                {
                    "protocol": "telnet",
                    "src_ip": src_ip,
                    "reason": reason,
                    "active_sessions": self.services.session.active_sessions,
                    "per_ip_sessions": self.services.session.sessions_per_ip.get(src_ip, 0),
                },
            )
            writer.close()
            return "", None, False

        session_id = str(uuid.uuid4())[:12]
        if not session_id.startswith("conn_"):
            session_id = "conn_" + session_id

        self.services.session.register_session(src_ip, session_id=session_id)
        folder_name = f"telnet_{src_ip}_{session_id}"
        log_dir = Path(self.logger.log_dir) / "tty" / folder_name
        log_dir.mkdir(parents=True, exist_ok=True)

        tty_paths = {
            "json": log_dir / "audit.json",
            "txt": log_dir / "transcript.log",
            "time": log_dir / "timing.time",
            "ml": log_dir / "ml_analysis.json",
        }

        for path in tty_paths.values():
            path.touch()

        self.logger.register_session_log(
            session_id, tty_paths["json"], tty_paths["ml"], src_ip=src_ip
        )

        self.logger.log_event(
            session_id,
            "session.start",
            {"protocol": "telnet", "src_ip": src_ip, "session_id": session_id},
        )

        class TTYState:
            def __init__(self):
                self.session_id = session_id
                self.src_ip = src_ip
                self.tty_log_path_json = tty_paths["json"]
                self.tty_log_path = tty_paths["txt"]
                self.tty_timing_path = tty_paths["time"]
                self.last_log_time = time.time()

        return session_id, TTYState(), True

    async def _send_banner(self, writer, fs) -> int:
        """Send the Telnet banner (issue file or default)."""
        try:
            from cyanide.vfs.nodes import File as VFSFile

            hostname = self.config.get("hostname", "server")
            issue_node = fs.get_node("/etc/issue")
            if issue_node and isinstance(issue_node, VFSFile):
                raw = issue_node.content or ""
            else:
                profile = getattr(self.server, "profile", {}) or {}
                os_name = profile.get("os_name", "")
                raw = f"{os_name} \\n \\l\n" if os_name else ""

            if not raw:
                return 0

            banner = raw.replace("\\n", hostname).replace("\\l", "pts/0").replace("\n", "\r\n")
            if not banner.endswith("\r\n"):
                banner += "\r\n"
            writer.write(banner.encode())
            await writer.drain()
            return len(banner)
        except Exception:
            return 0

    async def _perform_auth(self, reader, writer, session_id, src_ip) -> Tuple[bool, str, int, int]:
        """Handle login/password prompts and user validation."""
        bytes_in, bytes_out = 0, 0
        try:
            writer.write(self.LOGIN_PROMPT)
            bytes_out += len(self.LOGIN_PROMPT)
            self.stats.on_traffic("out", len(self.LOGIN_PROMPT))
            await writer.drain()
            login_data = await reader.readuntil(b"\n")
            bytes_in += len(login_data)
            self.stats.on_traffic("in", len(login_data))
            username = login_data.decode().strip()

            writer.write(self.PASSWORD_PROMPT)
            bytes_out += len(self.PASSWORD_PROMPT)
            self.stats.on_traffic("out", len(self.PASSWORD_PROMPT))
            await writer.drain()
            pass_data = await reader.readuntil(b"\n")
            bytes_in += len(pass_data)
            self.stats.on_traffic("in", len(pass_data))
            password = pass_data.decode().strip()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            self.logger.log_event(
                session_id,
                "telnet_disconnect",
                {"message": "Client disconnected during auth"},
            )
            return False, "", bytes_in, bytes_out

        success = self.server.is_valid_user(username, password)
        self.stats.on_auth(username, password, success)
        log_common = {"protocol": "telnet", "username": username, "success": success}

        log_password = password
        telnet_conf = self.config.get("telnet", {})
        if not telnet_conf.get("log_passwords", False):
            pass_hash = hashlib.sha256(password.encode()).hexdigest()
            log_password = f"sha256:{pass_hash} (len:{len(password)})"

        self.logger.log_event(
            session_id, "auth_attempt", {**log_common, "password_len": len(password)}
        )
        self.logger.log_event(
            session_id,
            "auth",
            {**log_common, "src_ip": src_ip, "password": log_password},
        )

        if success:
            auth_delay = self.config.get("telnet", {}).get("auth_delay", 1.0)
            if auth_delay > 0:
                await asyncio.sleep(auth_delay)

        if not success:
            self.services.analytics.analyze_auth(username, password, src_ip, session_id)
            resp = b"\r\nLogin incorrect\r\n"
            writer.write(resp)
            bytes_out += len(resp)
            await writer.drain()
            writer.close()

        return success, username, bytes_in, bytes_out

    async def _run_shell(
        self, reader, writer, shell, tty_state, session_id, src_ip, username
    ) -> Tuple[int, int, List[str]]:
        """Run the interactive shell command loop."""
        bytes_in, bytes_out = 0, 0
        commands = []
        prompt = f"{username}@server:~$ "

        # Initial prompt
        writer.write(prompt.encode())
        bytes_out += len(prompt)
        self.stats.on_traffic("out", len(prompt))
        self.server._log_tty(tty_state, "OUT", prompt)
        await writer.drain()

        while True:
            try:
                line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=self.session_timeout)
                bytes_in += len(line)
                self.stats.on_traffic("in", len(line))
                cmd = line.decode().strip()

                if not cmd:
                    prompt_bs = prompt.encode()
                    writer.write(prompt_bs)
                    bytes_out += len(prompt_bs)
                    self.stats.on_traffic("out", len(prompt_bs))
                    await writer.drain()
                    continue

                commands.append(cmd)
                self.server._log_tty(tty_state, "IN", cmd + "\n")
                if cmd in ("exit", "logout"):
                    break

                self.stats.on_command("telnet", src_ip, username, cmd)
                self.logger.log_event(
                    session_id,
                    "command.input",
                    {
                        "protocol": "telnet",
                        "src_ip": src_ip,
                        "username": username,
                        "input": cmd,
                        "cwd": shell.cwd,
                        "client_version": "Telnet",
                    },
                )
                self.services.analytics.analyze_command(cmd, src_ip, session_id)

                await asyncio.sleep(random.uniform(0.05, 0.3))
                stdout, stderr, rc = await shell.execute(cmd)

                if rc == 127:
                    self.stats.on_command_not_found(cmd)
                    self.logger.log_event(session_id, "command_not_found", {"cmd": cmd})

                output = (stdout + stderr).replace("\n", "\r\n").encode()
                writer.write(output)
                bytes_out += len(output)
                self.stats.on_traffic("out", len(output))
                self.server._log_tty(tty_state, "OUT", output)

                prompt = self._get_prompt(username, shell.cwd)
                writer.write(prompt.encode())
                bytes_out += len(prompt)
                self.stats.on_traffic("out", len(prompt))
                await writer.drain()

            except asyncio.TimeoutError:
                resp = b"\r\nTimeout.\r\n"
                writer.write(resp)
                bytes_out += len(resp)
                break

        return bytes_in, bytes_out, commands

    def _get_prompt(self, username: str, cwd: str) -> str:
        """Generate the shell prompt string based on current user and directory."""
        if cwd.startswith(f"/home/{username}"):
            cwd = cwd.replace(f"/home/{username}", "~", 1)
        elif username == "root" and cwd.startswith("/root"):
            cwd = cwd.replace("/root", "~", 1)
        return f"{username}@server:{cwd}$ "

    async def _cleanup_session(
        self,
        writer,
        session_id,
        src_ip,
        username,
        start_time,
        commands,
        bytes_in,
        bytes_out,
    ):
        """Finalize session logging and close connection."""
        duration = time.time() - start_time
        self.logger.log_event(
            session_id,
            "session.end",
            {
                "protocol": "telnet",
                "src_ip": src_ip,
                "username": username,
                "duration": duration,
                "command_count": len(commands),
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
            },
        )
        self.logger.unregister_session_log(session_id)
        self.services.session.unregister_session(session_id)
        self.stats.on_disconnect()
        writer.close()
        await writer.wait_closed()
