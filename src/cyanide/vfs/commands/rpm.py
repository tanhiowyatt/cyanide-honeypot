from .base import Command


class RpmCommand(Command):
    # Function 264: Executes the 'rpm' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        os_profile = getattr(self.fs, "os_profile", "centos").lower()
        if os_profile not in ["centos", "rhel", "fedora", "rocky", "almalinux", "custom"]:
            return "", "bash: rpm: command not found\n", 127

        if not args:
            return "RPM version 4.11.3\nCopyright (C) 1998-2002 - Red Hat, Inc.\n", "", 0

        action = args[0]

        if "-i" in action or action == "-ivh" or action == "-Uvh":
            targets = [a for a in args[1:] if not a.startswith("-")]
            if not targets:
                return "", "rpm: no packages given for install\n", 1

            output = ""
            for target in targets:
                target_path = self.emulator.resolve_path(target)
                if not self.fs.exists(target_path):
                    return "", f"error: open of {target} failed: No such file or directory\n", 1

                pkg_name = target.split("/")[-1].replace(".rpm", "")

                if self.fs.stats:
                    self.fs.stats.on_file_op("download", f"rpm://{pkg_name}")

                output += "Preparing...                          ################################# [100%]\n"
                output += "Updating / installing...\n"
                output += f"   1:{pkg_name:<29} ################################# [100%]\n"

            return output, "", 0

        elif "q" in action:
            if "a" in action:
                return (
                    (
                        "bash-4.2.46-35.el7_9.x86_64\n"
                        "coreutils-8.22-24.el7_9.2.x86_64\n"
                        "glibc-2.17-326.el7_9.x86_64\n"
                    ),
                    "",
                    0,
                )
            else:
                targets = [a for a in args[1:] if not a.startswith("-")]
                if targets:
                    return f"{targets[-1]}-1.0-1.el7.x86_64\n", "", 0
                return "rpm: no arguments given for query\n", "", 1

        return "", "rpm: unknown option\n", 1
