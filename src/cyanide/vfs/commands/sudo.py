from .base import Command


class SudoCommand(Command):
    """Execute a command as another user (mock)."""

    # Function 268: Executes the 'sudo' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute command as root or switch user."""
        target_user = "root"
        command_args = []

        i = 0
        interactive = False

        while i < len(args):
            arg = args[i]
            if arg == "-u":
                if i + 1 < len(args):
                    target_user = args[i + 1]
                    i += 2
                else:
                    return "", "sudo: option requires an argument -- 'u'\n", 1
            elif arg == "-l":
                return (
                    f"Matching Defaults entries for {self.emulator.username} on server:\n"
                    f"    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n"
                    f"User {self.emulator.username} may run the following commands on server:\n"
                    f"    (ALL : ALL) ALL\n",
                    "",
                    0,
                )
            elif arg == "-i" or arg == "-s":
                interactive = True
                i += 1
            elif arg.startswith("-"):
                i += 1
            else:
                command_args = args[i:]
                break

        if not command_args and not interactive:
            pass

        if not command_args:
            if interactive:
                self.emulator.username = target_user
                if target_user == "root":
                    self.emulator.cwd = "/root"
                    if not self.fs.exists("/root"):
                        self.emulator.cwd = "/"
                else:
                    self.emulator.cwd = f"/home/{target_user}"

                return "", "", 0
            else:
                return (
                    "",
                    "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\n",
                    1,
                )

        from cyanide.core.emulator import ShellEmulator

        temp_shell = ShellEmulator(self.fs, target_user, self.emulator.quarantine_callback)
        if not interactive:
            temp_shell.cwd = self.emulator.cwd

        import shlex

        cmd_line = shlex.join(command_args)

        stdout, stderr, rc = await temp_shell.execute(cmd_line)
        return stdout, stderr, rc
