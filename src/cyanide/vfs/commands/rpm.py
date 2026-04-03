import asyncio

from .base import Command


class RpmCommand(Command):

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        if not self._is_yummy_os():
            return "", "bash: rpm: command not found\n", 127

        if not args:
            return "RPM version 4.11.3\nCopyright (C) 1998-2002 - Red Hat, Inc.\n", "", 0

        action = args[0]
        packages = [a for a in args[1:] if not a.startswith("-")]

        if "-i" in action or action in ("-ivh", "-Uvh"):
            return self._handle_install(packages)
        elif "q" in action:
            return self._handle_query(action, packages)

        return "", "rpm: unknown option\n", 1

    def _is_yummy_os(self) -> bool:
        """Check if the current OS profile supports rpm."""
        os_profile = getattr(self.fs, "os_profile", "centos").lower()
        return os_profile in ["centos", "rhel", "fedora", "rocky", "almalinux", "custom"]

    def _handle_install(self, packages: list[str]) -> tuple[str, str, int]:
        """Handle package installation/update logic."""
        if not packages:
            return "", "rpm: no packages given for install\n", 1

        output = ""
        for pkg in packages:
            path = self.emulator.resolve_path(pkg)
            if not self.fs.exists(path):
                return "", f"error: open of {pkg} failed: No such file or directory\n", 1

            pkg_name = pkg.split("/")[-1].replace(".rpm", "")
            if self.fs.stats:
                self.fs.stats.on_file_op("download", f"rpm://{pkg_name}")

            output += (
                "Preparing...                          ################################# [100%]\n"
            )
            output += "Updating / installing...\n"
            output += f"   1:{pkg_name:<29} ################################# [100%]\n"

        return output, "", 0

    def _handle_query(self, action: str, packages: list[str]) -> tuple[str, str, int]:
        """Handle package query logic."""
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

        if packages:
            return f"{packages[-1]}-1.0-1.el7.x86_64\n", "", 0

        return "rpm: no arguments given for query\n", "", 1
