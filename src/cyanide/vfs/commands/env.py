from .base import Command


class EnvCommand(Command):
    async def execute(self, args, input_data=""):
        user = self.emulator.username
        home = "/root" if user == "root" else f"/home/{user}"
        env_vars = [
            f"USER={user}",
            f"HOME={home}",
            f"LOGNAME={user}",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM=xterm-256color",
            "SHELL=/bin/bash",
            "PWD=" + self.emulator.cwd,
            "LANG=en_US.UTF-8",
        ]
        return "\n".join(env_vars) + "\n", "", 0
