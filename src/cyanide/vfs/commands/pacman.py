import asyncio

from .base import Command


class PacmanCommand(Command):
    """Arch Linux package manager emulation."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        if not args:
            return "", "error: no operation specified (use -h for help)\n", 1

        op = args[0]
        if op in ("-S", "-Sy", "-Syu"):
            if len(args) < 2 and op == "-S":
                return "", "error: no targets specified (use -h for help)\n", 1

            package = args[1] if len(args) > 1 else "system"
            stdout = ":: Synchronizing package databases...\n"
            stdout += " core is up to date\n extra is up to date\n community is up to date\n"
            stdout += ":: Starting full system upgrade...\n"
            stdout += "resolving dependencies...\nlooking for conflicting packages...\n\n"
            stdout += f"Packages (1) {package}-1.0.0-1\n\n"
            stdout += "Total Download Size:   0.50 MiB\nTotal Installed Size:  1.20 MiB\n\n"
            stdout += ":: Proceed with installation? [Y/n] "

            # Simple simulation of "installation"
            stdout += "y\n"
            stdout += f"({package}) checking keys in keyring...\n"
            stdout += f"({package}) checking package integrity...\n"
            stdout += f"({package}) loading package files...\n"
            stdout += f"({package}) checking for file conflicts...\n"
            stdout += f"({package}) checking available disk space...\n"
            stdout += ":: Processing package changes...\n"
            stdout += f"(1/1) installing {package} [######################] 100%\n"

            # Create a fake binary if it's a specific package
            if package != "system":
                self.fs.mkfile(
                    f"/usr/bin/{package}",
                    content="#!/bin/bash\necho 'Emulated binary'\n",
                    perm="-rwxr-xr-x",
                )

            return stdout, "", 0

        elif op in ("-Q", "-Qi"):
            package = args[1] if len(args) > 1 else ""
            if not package:
                return "base 2023.01.01-1\nlinux 6.1.0-1\npacman 6.0.2-1\n", "", 0
            return (
                f"Name            : {package}\nVersion         : 1.0.0-1\nDescription     : Emulated package\nArchitecture    : x86_64\nURL             : https://archlinux.org\nLicenses        : GPL\nGroups          : None\nProvides        : None\nDepends On      : None\nOptional Deps   : None\nRequired By     : None\nOptional For    : None\nConflicts With  : None\nReplaces        : None\nInstalled Size  : 1.20 MiB\nPackager        : Unknown\nBuild Date      : Mon 01 Jan 2024\nInstall Date    : Tue 24 Mar 2026\nInstall Reason  : Explicitly installed\nInstall Script  : No\nValidated By    : Signature\n",
                "",
                0,
            )

        return "", f"error: invalid option '{op}'\n", 1
