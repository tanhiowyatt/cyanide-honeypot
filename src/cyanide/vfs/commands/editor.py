from .base import Command


class EditorCommand(Command):
    """Mock text editors (vi, nano, etc)."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        # Simple realism for honey-shell
        return "", "", 0
