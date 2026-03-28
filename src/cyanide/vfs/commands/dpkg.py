import asyncio

from .base import Command


class DpkgCommand(Command):
    # Function 225: Executes the 'dpkg' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the dpkg command."""
        if not self._is_dpkg_os():
            return "", "bash: dpkg: command not found\n", 127

        if not args:
            return "", "dpkg: error: need an action option\n", 2

        action = args[0]
        targets = args[1:]

        if action in ["-i", "--install"]:
            return self._handle_install(targets)

        if action in ["-l", "--list"]:
            return self._handle_list()

        return "", f"dpkg: error: unknown option {action}\n", 2

    def _is_dpkg_os(self) -> bool:
        """Check if the current OS profile supports dpkg."""
        os_profile = getattr(self.fs, "os_profile", "ubuntu").lower()
        return os_profile in ["ubuntu", "debian", "kali", "custom"]

    def _handle_install(self, targets: list[str]) -> tuple[str, str, int]:
        """Handle package installation."""
        if not targets:
            return (
                "",
                "dpkg: error: --install needs at least one package archive file argument\n",
                2,
            )

        output = ""
        for target in targets:
            target_path = self.emulator.resolve_path(target)
            if not self.fs.exists(target_path):
                return (
                    "",
                    f"dpkg: error: cannot access archive '{target}': No such file or directory\n",
                    2,
                )

            pkg_name = target.split("/")[-1].replace(".deb", "")

            if self.fs.stats:
                self.fs.stats.on_file_op("download", f"dpkg://{pkg_name}")

            output += f"Selecting previously unselected package {pkg_name}.\n"
            output += "(Reading database ... 10234 files and directories currently installed.)\n"
            output += f"Preparing to unpack {target} ...\n"
            output += f"Unpacking {pkg_name} (1.0) ...\n"
            output += f"Setting up {pkg_name} (1.0) ...\n"

        return output, "", 0

    def _handle_list(self) -> tuple[str, str, int]:
        """Handle package listing."""
        return (
            (
                "Desired=Unknown/Install/Remove/Purge/Hold\n"
                "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
                "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
                "||/ Name           Version      Architecture Description\n"
                "+++-==============-============-============-=================================\n"
                "ii  bash           5.1-6ubuntu1 amd64        GNU Bourne Again SHell\n"
                "ii  coreutils      8.32-4.1ubun amd64        GNU core utilities\n"
            ),
            "",
            0,
        )
