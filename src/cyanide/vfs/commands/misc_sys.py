import asyncio
import time

from .base import Command


class DateCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        # Mon Oct 25 14:00:00 UTC 2026
        return time.strftime("%a %b %d %H:%M:%S UTC %Y\n"), "", 0


class DfCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        output = (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "udev            3.9G     0  3.9G   0% /dev\n"
            "tmpfs           797M  1.6M  795M   1% /run\n"
            "/dev/sda1        40G  8.2G   30G  22% /\n"
            "tmpfs           3.9G     0  3.9G   0% /dev/shm\n"
            "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
            "tmpfs           3.9G     0  3.9G   0% /sys/fs/cgroup\n"
        )
        return output, "", 0
