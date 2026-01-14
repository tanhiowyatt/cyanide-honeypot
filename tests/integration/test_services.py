import pytest
import asyncio


@pytest.mark.asyncio


@pytest.mark.asyncio
async def test_mysql_service(honeypot_server):
    """Test MySQL vulnerable service handshake."""
    reader, writer = await asyncio.open_connection('127.0.0.1', 33060)
    
    try:
        data = await reader.read(1024)
        # Check for MariaDB version string in handshake
        assert b"MariaDB" in data
        assert len(data) > 4 # Minimal packet check
    finally:
        writer.close()
        await writer.wait_closed()
