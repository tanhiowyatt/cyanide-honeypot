import asyncio
import logging
import time
from typing import Any, Dict

logger = logging.getLogger(__name__)


class SMTPHandler:
    """
    Emulated SMTP handler for honeypot.
    """

    def __init__(self, server: Any, config: Dict[str, Any]):
        self.server = server
        self.config = config
        self.stats = getattr(server, "stats", None)
        self.logger = getattr(server, "logger", None)

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "unknown"
        session_id = f"smtp_{int(time.time())}"

        if self.logger:
            self.logger.log_event(
                session_id,
                "connect",
                {"protocol": "smtp", "src_ip": src_ip, "src_port": peer[1] if peer else 0},
            )

        try:
            hostname = self.server.config.get("honeypot", {}).get("hostname", "server01")
            banner = f"220 {hostname} ESMTP Postfix\r\n"
            writer.write(banner.encode())
            await writer.drain()

            while not reader.at_eof():
                line = await reader.readline()
                if not line:
                    break

                cmd_line = line.decode().strip()
                if not cmd_line:
                    continue

                if self.logger:
                    self.logger.log_event(
                        session_id,
                        "command.input",
                        {"protocol": "smtp", "src_ip": src_ip, "input": cmd_line},
                    )

                cmd = cmd_line.split()[0].upper() if cmd_line else ""

                if cmd in ("HELO", "EHLO"):
                    writer.write(f"250 {hostname} Hello {src_ip}\r\n".encode())
                elif cmd == "MAIL":
                    writer.write(b"250 2.1.0 Ok\r\n")
                elif cmd == "RCPT":
                    writer.write(b"250 2.1.5 Ok\r\n")
                elif cmd == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()
                    while True:
                        data_line = await reader.readline()
                        if not data_line or data_line.strip() == b".":
                            break
                    writer.write(b"250 2.0.0 Ok: queued as 12345\r\n")
                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                elif cmd == "VRFY":
                    writer.write(
                        b"252 2.1.5 Cannot VRFY user, but will accept message and attempt delivery\r\n"
                    )
                elif cmd == "NOOP":
                    writer.write(b"250 2.0.0 Ok\r\n")
                elif cmd == "RSET":
                    writer.write(b"250 2.0.0 Ok\r\n")
                else:
                    writer.write(b"502 5.5.2 Error: command not recognized\r\n")

                await writer.drain()

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            if self.logger:
                self.logger.log_event(session_id, "error", {"message": f"SMTP Error: {e}"})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if self.logger:
                self.logger.log_event(
                    session_id, "session_end", {"protocol": "smtp", "src_ip": src_ip}
                )
