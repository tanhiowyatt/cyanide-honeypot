from .base import Command

class IdCommand(Command):
    """Print user and group information for the specified user."""

    def execute(self, args: list[str]) -> tuple[str, str, int]:
        """Execute the id command.
        
        Returns:
            tuple: (uid_gid_info, empty_stderr, 0)
        """
        uid = 0 if self.username == "root" else 1000
        gid = 0 if self.username == "root" else 1000
        return f"uid={uid}({self.username}) gid={gid}({self.username}) groups={gid}({self.username})\n", "", 0
