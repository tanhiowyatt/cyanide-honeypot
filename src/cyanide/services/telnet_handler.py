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

    def __init__(self, server, config: Dict):
        self.server = server  # Reference to HoneypotServer for shared resources if needed
        self.config = config
        self.logger = server.logger
        self.services = server.services
        self.stats = server.stats

        self.session_timeout = config.get("session_timeout", 300)

    async def handle_connection(self, reader, writer):
        """Handle Telnet connection."""
        src_ip, src_port = writer.get_extra_info("peername")

        # Session Management
        accepted, reason = self.services.session.can_accept(src_ip)
        if not accepted:
            self.logger.log_event(
                "system", "connection_rejected", {"src_ip": src_ip, "reason": reason}
            )
            writer.close()
            return

        session_id = self.services.session.register_session(src_ip, "telnet")
        start_time = time.time()

        # Setup TTY logging
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
            await self.logger.log_event_async(
                {
                    "event": "connect",
                    "protocol": "telnet",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "session_id": session_id,
                }
            )

            # Analytics: GeoIP
            asyncio.create_task(self.services.analytics.log_geoip(session_id, src_ip, "telnet"))
            self.stats.on_connect("telnet", src_ip)

            # Simple auth
            writer.write(b"login: ")
            await writer.drain()
            username = (await reader.readuntil(b"\n")).decode().strip()

            writer.write(b"Password: ")
            await writer.drain()
            password = (await reader.readuntil(b"\n")).decode().strip()

            # Auth Check (delegated back to server or we move is_valid_user to a service?)
            # Server still holds users config for now.
            success = self.server.is_valid_user(username, password)
            self.stats.on_auth("telnet", src_ip, username, password, success)
            await self.logger.log_event_async(
                {
                    "event": "auth",
                    "protocol": "telnet",
                    "session_id": session_id,
                    "src_ip": src_ip,
                    "username": username,
                    "password": password,
                    "success": success,
                }
            )

            if not success:
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
                writer.close()
                return

            # Shell Setup
            fs = self.server.get_filesystem(session_id, src_ip)

            def quarantine_hook(f, c):
                self.services.quarantine.save_file(f, c, session_id, src_ip)

            shell = ShellEmulator(
                fs, username, quarantine_callback=quarantine_hook, config=self.config
            )

            prompt = f"{username}@server:~$ "
            writer.write(prompt.encode())
            self.server._log_tty(
                tty_state, "OUT", prompt
            )  # Keep using server's helper for now or move it?
            # It's better to duplicate/move _log_tty to a util or base class.
            # For now, let's copy the logic or assume server has it. Server has it.

            await writer.drain()

            while True:
                try:
                    line = await asyncio.wait_for(
                        reader.readuntil(b"\n"), timeout=self.session_timeout
                    )
                    cmd = line.decode().strip()
                    if not cmd:
                        writer.write(prompt.encode())
                        await writer.drain()
                        continue

                    commands.append(cmd)
                    self.server._log_tty(tty_state, "IN", cmd + "\n")

                    if cmd in ("exit", "logout"):
                        break

                    # Log & Analytics
                    self.stats.on_command("telnet", src_ip, username, cmd)
                    await self.logger.log_command(
                        session_id, "telnet", src_ip, username, cmd, client_version="Telnet"
                    )

                    # ML
                    self.services.analytics.analyze_command(
                        cmd, username, src_ip, session_id, "telnet"
                    )

                    # Jitter
                    await asyncio.sleep(random.uniform(0.05, 0.3))

                    stdout, stderr, rc = await shell.execute(cmd)

                    if rc == 127:
                        await self.logger.log_event_async(
                            {"event": "command_not_found", "session_id": session_id, "cmd": cmd}
                        )

                    output = stdout + stderr
                    resp = output.replace("\n", "\r\n").encode()
                    writer.write(resp)
                    self.server._log_tty(tty_state, "OUT", resp)

                    # Update prompt
                    cwd = shell.cwd
                    if cwd.startswith(f"/home/{username}"):
                        cwd = cwd.replace(f"/home/{username}", "~", 1)
                    elif username == "root" and cwd.startswith("/root"):
                        cwd = cwd.replace("/root", "~", 1)

                    prompt = f"{username}@server:{cwd}$ "
                    writer.write(prompt.encode())
                    await writer.drain()

                except asyncio.TimeoutError:
                    writer.write(b"\r\nTimeout.\r\n")
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
            await self.logger.log_event_async(
                {
                    "event": "session_end",
                    "protocol": "telnet",
                    "session_id": session_id,
                    "src_ip": src_ip,
                    "username": username,
                    "commands": commands,
                    "duration": duration,
                }
            )

            self.services.session.unregister_session(src_ip)
            self.stats.on_disconnect("telnet", src_ip)
            writer.close()
