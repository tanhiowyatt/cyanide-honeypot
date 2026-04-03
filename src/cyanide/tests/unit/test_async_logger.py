import asyncio
import tempfile
from pathlib import Path

import pytest

from cyanide.core.async_logger import AsyncLogger


@pytest.mark.asyncio
async def test_async_logger_writes():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.log"

        logger = AsyncLogger()
        logger.start()

        try:
            logger.log(log_file, "Line 1\n")
            logger.log(log_file, "Line 2\n")

            await asyncio.sleep(0.1)

            logger.log(log_file, "Line 3\n")

        finally:
            await logger.stop()

        assert log_file.exists()
        content = log_file.read_text()
        assert content == "Line 1\nLine 2\nLine 3\n"


@pytest.mark.asyncio
async def test_async_logger_binary():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = Path(tmpdir) / "test.bin"

        logger = AsyncLogger()
        logger.start()

        try:
            logger.log(log_file, b"\x00\x01\x02", mode="wb")
            logger.log(log_file, b"\x03\x04", mode="ab")
        finally:
            await logger.stop()

        content = log_file.read_bytes()
        assert content == b"\x00\x01\x02\x03\x04"
