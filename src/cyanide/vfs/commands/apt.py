from .base import Command


class AptCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        # Check OS profile support
        os_profile = getattr(self.fs, "os_profile", "ubuntu").lower()
        if os_profile not in ["ubuntu", "debian", "kali", "custom"]:
            return "", f"bash: {args[0] if args else 'apt'}: command not found\n", 127

        if not args:
            return (
                (
                    "apt 2.4.13 (amd64)\n"
                    "Usage: apt [options] command\n\n"
                    "apt is a commandline package manager.\n"
                ),
                "",
                0,
            )

        subcommand = args[0]
        packages = args[1:]

        if subcommand == "update":
            output = (
                "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
                "Get:2 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]\n"
                "Get:3 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [119 kB]\n"
                "Fetched 229 kB in 1s (229 kB/s)\n"
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                "All packages are up to date.\n"
            )
            return output, "", 0

        elif subcommand == "upgrade":
            return (
                (
                    "Reading package lists... Done\n"
                    "Building dependency tree... Done\n"
                    "Reading state information... Done\n"
                    "Calculating upgrade... Done\n"
                    "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
                ),
                "",
                0,
            )

        elif subcommand in ("install", "remove"):
            if not packages:
                return "", "E: No packages found\n", 100

            clean_pkgs = [p for p in packages if not p.startswith("-")]
            if not clean_pkgs:
                return "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", "", 0

            # Audit / Log installations
            if subcommand == "install":
                for pkg in clean_pkgs:
                    if self.fs.stats:
                        self.fs.stats.on_file_op("download", f"apt://{pkg}")

            verb = "Unpacking" if subcommand == "install" else "Removing"

            output = (
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
            )

            if subcommand == "install":
                output += (
                    f"The following NEW packages will be installed:\n  {' '.join(clean_pkgs)}\n"
                    f"0 upgraded, {len(clean_pkgs)} newly installed, 0 to remove and 0 not upgraded.\n"
                    "Need to get 0 B/1024 kB of archives.\n"
                    "After this operation, 3,141 kB of additional disk space will be used.\n"
                )

            # Simple interactive delay loop simulating installation
            for pkg in clean_pkgs:
                output += f"Selecting previously unselected package {pkg}.\n"
                output += f"Preparing to unpack .../{pkg}_amd64.deb ...\n"
                output += f"{verb} {pkg} (1.0-1) ...\n"
                output += f"Setting up {pkg} (1.0-1) ...\n"

            return output, "", 0

        elif subcommand == "search":
            if not packages:
                return "", "E: You must give at least one search pattern\n", 100

            return f"{packages[0]} - matching package library for {packages[0]}\n", "", 0

        return "", f"E: Invalid operation {subcommand}\n", 100
