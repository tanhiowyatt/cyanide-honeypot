from .base import Command


class SudoCommand(Command):
    """Execute a command as another user (mock)."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute command as root or switch user."""
        target_user = "root"
        command_args = []

        # Simple argument parsing
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
            elif arg == "-i" or arg == "-s":
                interactive = True
                i += 1
            elif arg.startswith("-"):
                # Ignore other flags for now (like -n)
                i += 1
            else:
                # Start of command
                command_args = args[i:]
                break

        # If no command, implies interactive shell logic?
        if not command_args and not interactive:
            # sudo without args usually shows usage or -s behavior?
            # On ubuntu 'sudo' showing usage. But 'sudo -i' is shell.
            # If just 'sudo', print usage? Or treat as -s?
            # Let's treat as usage.
            pass

        if not command_args:
            if interactive:
                # Switch current emulator to root!
                self.emulator.username = target_user
                if target_user == "root":
                    self.emulator.cwd = "/root"
                    # Ensure root dir exists (should be fixed now)
                    if not self.fs.exists("/root"):
                        self.emulator.cwd = "/"
                else:
                    self.emulator.cwd = f"/home/{target_user}"

                # We can't easily change the prompt in real-time until next loop,
                # but valid user change is persistent.
                return "", "", 0
            else:
                return (
                    "",
                    "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\n",
                    1,
                )

        # Execute command as target user
        # We need a new shell emulator for that user?
        # Or just temporary context?
        # Creating a new emulator is safest to isolate permissions logic.
        from cyanide.core.emulator import ShellEmulator

        temp_shell = ShellEmulator(self.fs, target_user, self.emulator.quarantine_callback)
        # Inherit CWD? Sudo usually keeps CWD unless -i
        if not interactive:
            temp_shell.cwd = self.emulator.cwd

        # We need to rejoin the command args into a command line string
        # This is a bit lossy but best we can do given args list
        import shlex

        cmd_line = shlex.join(command_args)

        stdout, stderr, rc = await temp_shell.execute(cmd_line)
        return stdout, stderr, rc
