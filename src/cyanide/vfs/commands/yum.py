import asyncio

from .base import Command


class YumCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        if not self._is_yummy_os():
            return "", f"bash: {args[0] if args else 'yum'}: command not found\n", 127

        if not args:
            return ("Loaded plugins: fastestmirror\n" + "You need to give some command\n"), "", 1

        subcommand = args[0]
        packages = args[1:]

        if subcommand in ("update", "upgrade"):
            return self._handle_update()
        elif subcommand in ("install", "remove", "erase"):
            return self._handle_install_remove(subcommand, packages)
        elif subcommand == "search":
            return self._handle_search(packages)

        return "Loaded plugins: fastestmirror\nNo such command: " + subcommand + ".\n", "", 1

    def _is_yummy_os(self) -> bool:
        """Check if the current OS profile supports yum/dnf."""
        os_profile = getattr(self.fs, "os_profile", "centos").lower()
        return os_profile in ["centos", "rhel", "fedora", "rocky", "almalinux", "custom"]

    def _handle_update(self) -> tuple[str, str, int]:
        """Handle update and upgrade subcommands."""
        return (
            (
                "Loaded plugins: fastestmirror\n"
                "Loading mirror speeds from cached hostfile\n"
                "No packages marked for update\n"
            ),
            "",
            0,
        )

    def _handle_install_remove(self, subcommand: str, packages: list[str]) -> tuple[str, str, int]:
        """Handle install, remove, and erase subcommands."""
        if not packages:
            return (
                "Loaded plugins: fastestmirror\nError: Need to pass a list of pkgs to install\n",
                "",
                1,
            )

        clean_pkgs = [p for p in packages if not p.startswith("-")]
        if not clean_pkgs:
            return "Loaded plugins: fastestmirror\nNo packages provided.\n", "", 0

        if subcommand == "install":
            self._track_pkg_downloads(clean_pkgs)

        action = "Installing" if subcommand == "install" else "Erasing"
        output = self._generate_transaction_output(action, clean_pkgs)
        return output, "", 0

    def _track_pkg_downloads(self, packages: list[str]):
        """Log package downloads in filesystem stats."""
        for pkg in packages:
            if self.fs.stats:
                self.fs.stats.on_file_op("download", f"yum://{pkg}")

    def _generate_transaction_output(self, action: str, packages: list[str]) -> str:
        """Generate the detailed yum transaction output."""
        output = (
            "Loaded plugins: fastestmirror\n"
            "Loading mirror speeds from cached hostfile\n"
            "Resolving Dependencies\n"
            "--> Running transaction check\n"
        )

        for pkg in packages:
            output += f"---> Package {pkg}.x86_64 0:1.0-1.el7 will be {action.lower()}\n"

        output += (
            "--> Finished Dependency Resolution\n\n"
            "Dependencies Resolved\n\n"
            "================================================================================\n"
            " Package             Arch             Version           Repository        Size\n"
            "================================================================================\n"
        )
        for pkg in packages:
            output += f" {action[:10]:<19} {pkg:<16} x86_64           1.0-1.el7         base              42 k\n"

        output += (
            "\nTransaction Summary\n"
            "================================================================================\n"
            f"{action}  {len(packages)} Package(s)\n\n"
            "Total download size: 42 k\n"
            f"{action} size: 100 k\n"
            "Downloading packages:\n"
            "Running transaction check\n"
            "Running transaction test\n"
            "Transaction test succeeded\n"
            "Running transaction\n"
        )

        for i, pkg in enumerate(packages, 1):
            progress = (i * 100) // len(packages)
            output += f"  {action:<11}: {pkg}-1.0-1.el7.x86_64{progress:>30}/{len(packages)}\n"

        output += "\nComplete!\n"
        return output

    def _handle_search(self, packages: list[str]) -> tuple[str, str, int]:
        """Handle search subcommand."""
        if not packages:
            return "Error: Need to pass a list of pkgs to search\n", "", 1

        return (
            (
                "Loaded plugins: fastestmirror\n"
                "Loading mirror speeds from cached hostfile\n"
                f"============================= N/S matched: {packages[0]} =============================\n"
                f"{packages[0]}.x86_64 : Matched package for {packages[0]}\n"
            ),
            "",
            0,
        )
