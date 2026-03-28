import asyncio

from .base import Command


class PsCommand(Command):
    """Report a snapshot of the current processes."""

    # Function 257: Executes the 'ps' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the ps command.

        Returns:
            tuple: (process_list, empty_stderr, 0)
        """
        profile = getattr(self.fs, "profile", None)

        if hasattr(self.fs, "processes"):
            processes = list(self.fs.processes)
        elif profile and "processes" in profile:
            processes = list(profile["processes"])
        else:
            processes = [
                {"pid": 1, "tty": "?", "time": "00:00:15", "cmd": "/sbin/init"},
                {"pid": 2, "tty": "?", "time": "00:00:00", "cmd": "[kthreadd]"},
                {"pid": 890, "tty": "?", "time": "00:00:04", "cmd": "/usr/sbin/sshd -D"},
            ]

        import secrets

        mypid = secrets.SystemRandom().randint(10000, 32000)
        processes.append({"pid": mypid, "tty": "pts/0", "time": "00:00:00", "cmd": "-bash"})
        processes.append({"pid": mypid + 1, "tty": "pts/0", "time": "00:00:00", "cmd": "ps"})

        if "aux" in args or "a" in args or "-aux" in args:
            output = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            for p in processes:
                user = "root" if p["pid"] < 1000 else self.username
                output += f"{user:<10} {p.get('pid', 0):>5}  0.0  0.1  123456  1234 {p.get('tty', '?'):<8} Ss   09:00   {p.get('time', '00:00:00')} {p.get('cmd', '')}\n"
        else:
            output = "    PID TTY          TIME CMD\n"
            for p in processes:
                output += f"{p.get('pid', 0):>7} {p.get('tty', '?'):<8} {p.get('time', '00:00:00')} {p.get('cmd', '')}\n"

        return output, "", 0
