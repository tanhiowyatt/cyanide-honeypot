import asyncio
import time
from typing import Any, Dict


class SMTPHandler:
    """
    Emulated SMTP handler for honeypot.
    """

    def __init__(self, server: Any, config: Dict[str, Any]):
        self.server = server
        self.config = config
        self.stats = getattr(server, "stats", None)
        self.logger = getattr(server, "logger", None)
        self._dispatch_map = {
            "HELO": self._cmd_helo,
            "EHLO": self._cmd_helo,
            "MAIL": self._cmd_mail,
            "RCPT": self._cmd_rcpt,
            "DATA": self._cmd_data,
            "QUIT": self._cmd_quit,
            "VRFY": self._cmd_vrfy,
            "NOOP": self._cmd_noop,
            "RSET": self._cmd_rset,
        }

    def _init_session(self, writer: asyncio.StreamWriter):
        import uuid

        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "unknown"
        session_id = f"smtp_{str(uuid.uuid4())[:8]}"
        hostname = self.server.config.get("honeypot", {}).get("hostname", "server01")

        if self.logger:
            self.logger.log_event(
                session_id,
                "connect",
                {
                    "protocol": "smtp",
                    "src_ip": src_ip,
                    "src_port": peer[1] if peer else 0,
                },
            )
        if self.stats:
            self.stats.on_connect("smtp", src_ip)
        return src_ip, session_id, hostname, time.time()

    async def _command_loop(self, reader, writer, session_id, src_ip, hostname):
        while not reader.at_eof():
            line = await reader.readline()
            if not line:
                break

            cmd_line = line.decode().strip()
            if not cmd_line:
                continue

            cmd, args = self._parse_and_log_command(cmd_line, session_id, src_ip)
            should_continue = await self._handle_command(
                reader, writer, cmd, args, src_ip, hostname
            )

            if not should_continue:
                break

            await writer.drain()

    def _parse_and_log_command(self, cmd_line, session_id, src_ip):
        if self.logger:
            self.logger.log_event(
                session_id,
                "command.input",
                {"protocol": "smtp", "src_ip": src_ip, "input": cmd_line},
            )

        parts = cmd_line.split()
        cmd = parts[0].upper() if parts else ""
        args = parts[1:] if len(parts) > 1 else []
        return cmd, args

    async def _handle_command(self, reader, writer, cmd, args, src_ip, hostname) -> bool:
        handler = self._dispatch_map.get(cmd)
        if handler:
            return await handler(reader, writer, args, src_ip, hostname)

        writer.write(b"502 5.5.2 Error: command not recognized\r\n")
        return True

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        src_ip, session_id, hostname, start_time = self._init_session(writer)

        try:
            writer.write(f"220 {hostname} ESMTP Postfix\r\n".encode())
            await writer.drain()

            await self._command_loop(reader, writer, session_id, src_ip, hostname)

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            if self.logger:
                self.logger.log_event(session_id, "error", {"message": f"SMTP Error: {e}"})
        finally:
            await self._cleanup(writer, session_id, src_ip, start_time)

    async def _cleanup(self, writer, session_id, src_ip, start_time):
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        duration = time.time() - start_time
        if self.logger:
            self.logger.log_event(
                session_id,
                "session.end",
                {"protocol": "smtp", "src_ip": src_ip, "duration": round(duration, 2)},
            )
        if self.stats:
            self.stats.on_disconnect()

    async def _cmd_helo(self, reader, writer, args, src_ip, hostname) -> bool:
        writer.write(f"250 {hostname} Hello {src_ip}\r\n".encode())
        await writer.drain()
        return True

    async def _cmd_mail(self, reader, writer, args, src_ip, hostname) -> bool:
        writer.write(b"250 2.1.0 Ok\r\n")
        await writer.drain()
        return True

    async def _cmd_rcpt(self, reader, writer, args, src_ip, hostname) -> bool:
        writer.write(b"250 2.1.5 Ok\r\n")
        await writer.drain()
        return True

    async def _cmd_data(self, reader, writer, args, src_ip, hostname) -> bool:
        writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        await writer.drain()
        while True:
            data_line = await reader.readline()
            if not data_line or data_line.strip() == b".":
                break
        writer.write(b"250 2.0.0 Ok: queued as 12345\r\n")
        return True

    async def _cmd_quit(self, reader, writer, args, src_ip, hostname) -> bool:
        writer.write(b"221 2.0.0 Bye\r\n")
        await writer.drain()
        return False

    async def _cmd_vrfy(self, reader, writer, args, src_ip, hostname) -> bool:
        writer.write(
            b"252 2.1.5 Cannot VRFY user, but will accept message and attempt delivery\r\n"
        )
        await writer.drain()
        return True

    async def _cmd_noop(self, reader, writer, args, src_ip, hostname) -> bool:
        writer.write(b"250 2.0.0 Ok\r\n")
        await writer.drain()
        return True

    async def _cmd_rset(self, reader, writer, args, src_ip, hostname) -> bool:
        writer.write(b"250 2.0.0 Reset state\r\n")
        await writer.drain()
        return True
