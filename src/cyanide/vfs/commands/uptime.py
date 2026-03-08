import time

from .base import Command


class UptimeCommand(Command):
    """Tell how long the system has been running."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        # Try to get uptime from /proc/uptime
        uptime_content = self.fs.get_content("/proc/uptime")
        if not uptime_content:
            uptime_seconds = 3600.0  # Fallback
        else:
            try:
                uptime_seconds = float(uptime_content.split()[0])
            except (ValueError, IndexError):
                uptime_seconds = 3600.0

        # Format: 10:45:01 up 1:23, 1 user, load average: 0.05, 0.03, 0.05
        current_time = time.strftime("%H:%M:%S")
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        up_str = f"{hours}:{minutes:02}" if hours > 0 else f"{minutes} min"

        output = f" {current_time} up {up_str},  1 user,  load average: 0.00, 0.01, 0.05\n"
        return output, "", 0
