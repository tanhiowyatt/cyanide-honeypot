from .base import Command


class ExportCommand(Command):
    """Set environment variables (mock)."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the export command.

        Note:
            This is a mock implementation that does nothing but return success,
            as SSH clients often send export commands on startup.

        Returns:
            tuple: (stdout, stderr, 0)
        """
        # Allow export command but do nothing (fake success)
        # Often SSH clients send 'export LANG=...' on startup
        return "", "", 0
