import asyncio
import logging
import json

logger = logging.getLogger("cyanide")

class TCPProxy:
    """
    Generic TCP Proxy for forwarding traffic to another service (e.g., Mailoney).
    Logs connection metadata and data volume.
    """
    def __init__(self, listen_host, listen_port, target_host=None, target_port=None, protocol_name="tcp", target_selector=None):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.protocol_name = protocol_name
        self.target_selector = target_selector # Callable returning (host, port)
        self.server = None

    async def start(self):
        """Start the TCP Proxy server."""
        self.server = await asyncio.start_server(
            self.handle_client, self.listen_host, self.listen_port
        )
        print(f"[*] {self.protocol_name.upper()} Proxy listening on {self.listen_host}:{self.listen_port} -> {self.target_host}:{self.target_port}")
        return self.server

    async def handle_client(self, client_reader, client_writer):
        """Handle incoming client connection."""
        src_ip, src_port = client_writer.get_extra_info('peername')
        
        # Log connection
        logger.info(json.dumps({
            "event": "proxy_connect",
            "protocol": self.protocol_name,
            "src_ip": src_ip,
            "src_port": src_port,
            "target": f"{self.target_host}:{self.target_port}"
        }))

        try:
            # Determine target
            if self.target_selector:
                res = self.target_selector()
                if res:
                    tgt_host, tgt_port = res
                else:
                    print(f"[!] {self.protocol_name.upper()} Proxy: No target available from pool.")
                    client_writer.close()
                    return
            else:
                tgt_host, tgt_port = self.target_host, self.target_port

            # Connect to target
            print(f"[*] Proxying {src_ip} -> {tgt_host}:{tgt_port}")
            target_reader, target_writer = await asyncio.open_connection(
                tgt_host, tgt_port
            )
        except Exception as e:
            print(f"[!] {self.protocol_name.upper()} Proxy: Failed to connect to target: {e}")
            client_writer.close()
            return

        # Create tasks for bidirectional forwarding
        client_to_target = asyncio.create_task(self.forward(client_reader, target_writer, "client_to_target"))
        target_to_client = asyncio.create_task(self.forward(target_reader, client_writer, "target_to_client"))

        # Wait for either to finish
        done, pending = await asyncio.wait(
            [client_to_target, target_to_client],
            return_when=asyncio.FIRST_COMPLETED
        )

        # Cancel pending
        for task in pending:
            task.cancel()
            
        # Close connections
        target_writer.close()
        client_writer.close()
        await target_writer.wait_closed()
        await client_writer.wait_closed()

    async def forward(self, reader, writer, direction):
        """Forward data between reader and writer."""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                # Monitor/Log payload
                # Log only first 50 bytes to avoid spam, or specific patterns?
                # For monitoring, we might want full capture (hex encoded).
                if len(data) > 0:
                     logger.info(json.dumps({
                         "event": "proxy_data",
                         "protocol": self.protocol_name,
                         "direction": direction,
                         "len": len(data),
                         "data_hex": data.hex()[:100] + ("..." if len(data) > 100 else "")
                     }))
                
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
