import asyncio
import random
import time
import traceback
from pathlib import Path
from typing import Dict

from cyanide.core.emulator import ShellEmulator


class TelnetHandler:
    """
    Handles Telnet connections and interactive shell emulation.
    """

    # Function 195: Initializes the class instance and its attributes.
    def __init__(self, server, config: Dict):
        self.server = server
        self.config = config
        self.logger = server.logger
        self.services = server.services
        self.stats = server.stats

        self.session_timeout = config.get("session_timeout", 300)

    # Function 196: Handles incoming connection events.
    async def handle_connection(self, reader, writer):
        """Handle Telnet connection."""
        src_ip, src_port = writer.get_extra_info("peername")

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
            return

        session_id = self.services.session.register_session(src_ip, "telnet")
        start_time = time.time()

        folder_name = f"telnet_{src_ip}_{session_id}"
        log_dir = Path(self.logger.log_dir) / "tty" / folder_name
        log_dir.mkdir(parents=True, exist_ok=True)

        tty_log_path = log_dir / f"{folder_name}.jsonl"
        tty_log_txt = log_dir / f"{folder_name}.log"
        tty_timing = log_dir / f"{folder_name}.time"

        open(tty_log_path, "w").close()
        open(tty_log_txt, "w").close()
        open(tty_timing, "w").close()

        class TTYState:
            tty_log_path_jsonl: Path
            tty_log_path: Path
            tty_timing_path: Path
            last_log_time: float

        tty_state = TTYState()
        tty_state.tty_log_path_jsonl = tty_log_path
        tty_state.tty_log_path = tty_log_txt
        tty_state.tty_timing_path = tty_timing
        tty_state.last_log_time = time.time()

        commands = []
        username = ""

        try:
            self.logger.log_event(
                session_id,
                "connect",
                {
                    "protocol": "telnet",
                    "src_ip": src_ip,
                    "src_port": src_port,
                },
            )

            asyncio.create_task(self.services.analytics.log_geoip(session_id, src_ip, "telnet"))
            self.stats.on_connect("telnet", src_ip)

            fs = self.server.get_filesystem(session_id, src_ip)

            bytes_in = 0
            bytes_out = 0

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
                if raw:
                    raw = raw.replace("\\n", hostname).replace("\\l", "pts/0")
                    banner = raw.replace("\n", "\r\n")
                    if not banner.endswith("\r\n"):
                        banner += "\r\n"
                    bs = banner.encode()
                    writer.write(bs)
                    bytes_out += len(bs)
                    await writer.drain()
            except Exception:
                pass

            try:
                writer.write(b"login: ")
                bytes_out += len(b"login: ")
                self.stats.on_traffic("out", len(b"login: "))
                await writer.drain()
                login_data = await reader.readuntil(b"\n")
                bytes_in += len(login_data)
                self.stats.on_traffic("in", len(login_data))
                username = login_data.decode().strip()

                writer.write(b"Password: ")
                bytes_out += len(b"Password: ")
                self.stats.on_traffic("out", len(b"Password: "))
                await writer.drain()
                pass_data = await reader.readuntil(b"\n")
                bytes_in += len(pass_data)
                self.stats.on_traffic("in", len(pass_data))
                password = pass_data.decode().strip()
            except (asyncio.IncompleteReadError, ConnectionResetError):
                self.logger.log_event(
                    session_id, "telnet_disconnect", {"message": "Client disconnected during auth"}
                )
                return False, bytes_in, bytes_out, "", False

            success = self.server.is_valid_user(username, password)
            self.stats.on_auth("telnet", src_ip, username, password, success)

            self.logger.log_event(
                session_id,
                "auth_attempt",
                {
                    "protocol": "telnet",
                    "username": username,
                    "password_len": len(password),
                    "success": success,
                },
            )

            self.logger.log_event(
                session_id,
                "auth",
                {
                    "protocol": "telnet",
                    "src_ip": src_ip,
                    "username": username,
                    "password": password,
                    "success": success,
                },
            )

            if not success:
                resp = b"\r\nLogin incorrect\r\n"
                bytes_out += len(resp)
                writer.write(resp)
                await writer.drain()
                writer.close()
                return

            self.logger.log_event(
                session_id,
                "session_start",
                {"protocol": "telnet", "src_ip": src_ip, "session_id": session_id},
            )

            # Function 197: Performs operations related to quarantine hook.
            def quarantine_hook(f, c):
                self.services.quarantine.save_file(f, c, session_id, src_ip)

            shell = ShellEmulator(
                fs, username, quarantine_callback=quarantine_hook, config=self.config
            )

            prompt = f"{username}@server:~$ "
            prompt_bs = prompt.encode()
            writer.write(prompt_bs)
            bytes_out += len(prompt_bs)
            self.stats.on_traffic("out", len(prompt_bs))
            self.server._log_tty(tty_state, "OUT", prompt)

            await writer.drain()

            while True:
                try:
                    line = await asyncio.wait_for(
                        reader.readuntil(b"\n"), timeout=self.session_timeout
                    )
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

                    self.services.analytics.analyze_command(
                        cmd, username, src_ip, session_id, "telnet"
                    )

                    await asyncio.sleep(random.uniform(0.05, 0.3))

                    stdout, stderr, rc = await shell.execute(cmd)

                    if rc == 127:
                        self.stats.on_command_not_found(cmd)
                        self.logger.log_event(session_id, "command_not_found", {"cmd": cmd})

                    output = stdout + stderr
                    resp = output.replace("\n", "\r\n").encode()
                    writer.write(resp)
                    bytes_out += len(resp)
                    self.stats.on_traffic("out", len(resp))
                    self.server._log_tty(tty_state, "OUT", resp)

                    cwd = shell.cwd
                    if cwd.startswith(f"/home/{username}"):
                        cwd = cwd.replace(f"/home/{username}", "~", 1)
                    elif username == "root" and cwd.startswith("/root"):
                        cwd = cwd.replace("/root", "~", 1)

                    prompt = f"{username}@server:{cwd}$ "
                    prompt_bs = prompt.encode()
                    writer.write(prompt_bs)
                    bytes_out += len(prompt_bs)
                    self.stats.on_traffic("out", len(prompt_bs))
                    await writer.drain()

                except asyncio.TimeoutError:
                    resp = b"\r\nTimeout.\r\n"
                    bytes_out += len(resp)
                    writer.write(resp)
                    break
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
            duration = time.time() - start_time
            self.logger.log_event(
                session_id,
                "session_end",
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

            self.services.session.unregister_session(src_ip)
            self.stats.on_disconnect("telnet", src_ip)
            writer.close()
