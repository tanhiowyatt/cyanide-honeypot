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
        
        # Base processes common to Linux
        processes = [
            {"pid": 1, "tty": "?", "time": "00:00:15", "cmd": "/sbin/init"},
            {"pid": 2, "tty": "?", "time": "00:00:00", "cmd": "[kthreadd]"},
            {"pid": 3, "tty": "?", "time": "00:00:00", "cmd": "[rcu_gp]"},
            {"pid": 4, "tty": "?", "time": "00:00:00", "cmd": "[rcu_par_gp]"},
            {"pid": 6, "tty": "?", "time": "00:00:00", "cmd": "[kworker/0:0H-kblockd]"},
            {"pid": 9, "tty": "?", "time": "00:00:00", "cmd": "[mm_percpu_wq]"},
            {"pid": 10, "tty": "?", "time": "00:00:00", "cmd": "[rcu_tasks_kthre]"},
            {"pid": 345, "tty": "?", "time": "00:00:02", "cmd": "/lib/systemd/systemd-journald"},
            {"pid": 367, "tty": "?", "time": "00:00:01", "cmd": "/lib/systemd/systemd-udevd"},
            {"pid": 580, "tty": "?", "time": "00:00:00", "cmd": "/usr/sbin/cron -f"},
            {"pid": 585, "tty": "?", "time": "00:00:00", "cmd": "/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only"},
            {"pid": 645, "tty": "?", "time": "00:00:00", "cmd": "/usr/sbin/rsyslogd -n -iNONE"},
            {"pid": 890, "tty": "?", "time": "00:00:04", "cmd": "/usr/sbin/sshd -D"},
        ]
        
        # Profile adjustments
        if profile and "centos" in profile.get("name", "").lower():
            processes[0]["cmd"] = "/usr/lib/systemd/systemd --switched-root --system --deserialize 22"
            
        # Add current user shell
        import random
        mypid = random.randint(10000, 32000)
        processes.append({"pid": mypid, "tty": "pts/0", "time": "00:00:00", "cmd": "-bash"})
        processes.append({"pid": mypid+1, "tty": "pts/0", "time": "00:00:00", "cmd": "ps"})
        
        output = "    PID TTY          TIME CMD\n"
        for p in processes:
            output += f"{p['pid']:>7} {p['tty']:<8} {p['time']} {p['cmd']}\n"
            
        return output, "", 0
