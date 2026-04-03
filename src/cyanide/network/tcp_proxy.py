import asyncio
import json
import logging

logger = logging.getLogger("cyanide")


class TCPProxy:
    """
    Generic TCP Proxy for forwarding traffic to another service (e.g., Mailoney).
    Logs connection metadata and data volume.
    """

    def __init__(
        self,
        listen_host,
        listen_port,
        target_host=None,
        target_port=None,
        protocol_name="tcp",
        pool=None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.protocol_name = protocol_name
        self.pool = pool
        self.server = None

    async def start(self):
        """Start the TCP Proxy server."""
        self.server = await asyncio.start_server(
            self.handle_client, self.listen_host, self.listen_port
        )
        logger.info(
            f"{self.protocol_name.upper()} Proxy listening on {self.listen_host}:{self.listen_port} -> {self.target_host}:{self.target_port}"
        )
        return self.server

    def close(self):
        """Stop the TCP Proxy server."""
        if self.server:
            self.server.close()

    async def wait_closed(self):
        """Wait for the TCP Proxy server to stop."""
        if self.server:
            await self.server.wait_closed()

    async def handle_client(self, client_reader, client_writer):
        """Handle incoming client connection."""
        src_ip, src_port = client_writer.get_extra_info("peername")

        logger.info(
            json.dumps(
                {
                    "event": "proxy_connect",
                    "protocol": self.protocol_name,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "target": f"{self.target_host}:{self.target_port}",
                }
            )
        )

        import uuid

        session_id = str(uuid.uuid4())
        lease = None

        try:
            if self.pool:
                lease = await self.pool.reserve_target(session_id, self.protocol_name)
                if lease:
                    if hasattr(lease, "host"):
                        tgt_host, tgt_port = lease.host, lease.port
                    else:
                        tgt_host, tgt_port = lease[0], lease[1]
                else:
                    logger.error(
                        f"{self.protocol_name.upper()} Proxy: No target available from pool."
                    )
                    client_writer.close()
                    return
            else:
                tgt_host, tgt_port = self.target_host, self.target_port

            logger.debug(f"Proxying {src_ip} -> {tgt_host}:{tgt_port}")
            target_reader, target_writer = await asyncio.open_connection(tgt_host, tgt_port)
        except Exception as e:
            logger.error(f"{self.protocol_name.upper()} Proxy: Failed to connect to target: {e}")
            client_writer.close()
            return

        try:
            client_to_target = asyncio.create_task(
                self.forward(client_reader, target_writer, "client_to_target")
            )
            target_to_client = asyncio.create_task(
                self.forward(target_reader, client_writer, "target_to_client")
            )

            _, pending = await asyncio.wait(
                [client_to_target, target_to_client], return_when=asyncio.FIRST_COMPLETED
            )

            for task in pending:
                task.cancel()
        finally:
            target_writer.close()
            client_writer.close()
            await target_writer.wait_closed()
            await client_writer.wait_closed()

            if self.pool and lease:
                await self.pool.release_target(lease)

    async def forward(self, reader, writer, direction):
        """Forward data between reader and writer."""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                if len(data) > 0:
                    logger.info(
                        json.dumps(
                            {
                                "event": "proxy_data",
                                "protocol": self.protocol_name,
                                "direction": direction,
                                "len": len(data),
                                "data_hex": data.hex()[:100] + ("..." if len(data) > 100 else ""),
                            }
                        )
                    )

                writer.write(data)
                await writer.drain()
        except Exception:
            pass
