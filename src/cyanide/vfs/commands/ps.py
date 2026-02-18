from .base import Command


class PsCommand(Command):
    """Report a snapshot of the current processes."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the ps command.

        Returns:
            tuple: (process_list, empty_stderr, 0)
        """
        # Get Profile from FS
        profile = getattr(self.fs, "profile", None)

        if profile and "processes" in profile:
            processes = list(profile["processes"])
        else:
            # Fallback common to Linux if no profile data
            processes = [
                {"pid": 1, "tty": "?", "time": "00:00:15", "cmd": "/sbin/init"},
                {"pid": 2, "tty": "?", "time": "00:00:00", "cmd": "[kthreadd]"},
                {"pid": 890, "tty": "?", "time": "00:00:04", "cmd": "/usr/sbin/sshd -D"},
            ]

        # Add current user shell dynamically
        import random

        mypid = random.randint(10000, 32000)
        processes.append({"pid": mypid, "tty": "pts/0", "time": "00:00:00", "cmd": "-bash"})
        processes.append({"pid": mypid + 1, "tty": "pts/0", "time": "00:00:00", "cmd": "ps"})

        output = "    PID TTY          TIME CMD\n"
        for p in processes:
            output += f"{p.get('pid', 0):>7} {p.get('tty', '?'):<8} {p.get('time', '00:00:00')} {p.get('cmd', '')}\n"

        return output, "", 0
