from .base import Command


class YumCommand(Command):
    # Function 279: Executes the 'yum' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        os_profile = getattr(self.fs, "os_profile", "centos").lower()
        if os_profile not in ["centos", "rhel", "fedora", "rocky", "almalinux", "custom"]:
            return "", f"bash: {args[0] if args else 'yum'}: command not found\n", 127

        if not args:
            return ("Loaded plugins: fastestmirror\n" "You need to give some command\n"), "", 1

        subcommand = args[0]
        packages = args[1:]

        if subcommand == "update" or subcommand == "upgrade":
            return (
                (
                    "Loaded plugins: fastestmirror\n"
                    "Loading mirror speeds from cached hostfile\n"
                    "No packages marked for update\n"
                ),
                "",
                0,
            )

        elif subcommand in ("install", "remove", "erase"):
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
                for pkg in clean_pkgs:
                    if self.fs.stats:
                        self.fs.stats.on_file_op("download", f"yum://{pkg}")

            action = "Installing" if subcommand == "install" else "Erasing"

            output = (
                "Loaded plugins: fastestmirror\n"
                "Loading mirror speeds from cached hostfile\n"
                "Resolving Dependencies\n"
                "--> Running transaction check\n"
            )

            for pkg in clean_pkgs:
                output += f"---> Package {pkg}.x86_64 0:1.0-1.el7 will be {action.lower()}\n"

            output += (
                "--> Finished Dependency Resolution\n\n"
                "Dependencies Resolved\n\n"
                "================================================================================\n"
                " Package             Arch             Version           Repository        Size\n"
                "================================================================================\n"
            )
            for pkg in clean_pkgs:
                output += f" {action[:10]:<19} {pkg:<16} x86_64           1.0-1.el7         base              42 k\n"

            output += (
                "\nTransaction Summary\n"
                "================================================================================\n"
                f"{action}  {len(clean_pkgs)} Package(s)\n\n"
                "Total download size: 42 k\n"
                f"{action} size: 100 k\n"
                "Downloading packages:\n"
                "Running transaction check\n"
                "Running transaction test\n"
                "Transaction test succeeded\n"
                "Running transaction\n"
            )

            for i, pkg in enumerate(clean_pkgs, 1):
                output += f"  {action:<11}: {pkg}-1.0-1.el7.x86_64{((i*len(clean_pkgs))//len(clean_pkgs)):>30}/{len(clean_pkgs)}\n"

            output += "\nComplete!\n"
            return output, "", 0

        elif subcommand == "search":
            if not packages:
                return "Error: Need to pass a list of pkgs to search\n", "", 1

            return (
                (
                    "Loaded plugins: fastestmirror\n"
                    "Loading mirror speeds from cached hostfile\n"
                    "============================= N/S matched: {packages[0]} =============================\n"
                    f"{packages[0]}.x86_64 : Matched package for {packages[0]}\n"
                ),
                "",
                0,
            )

        return "Loaded plugins: fastestmirror\nNo such command: " + subcommand + ".\n", "", 1
