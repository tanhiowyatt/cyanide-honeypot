import asyncio
import secrets

from .base import Command


class SystemctlCommand(Command):
    # Function 269: Executes the 'systemctl' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if "status" in args:
            service = (
                args[args.index("status") + 1] if args.index("status") + 1 < len(args) else "ssh"
            )
            rng = secrets.SystemRandom()
            return (
                (
                    f"● {service}.service - {service.capitalize()} Service\n"
                    f"   Loaded: loaded (/lib/systemd/system/{service}.service; enabled; vendor preset: enabled)\n"
                    "   Active: active (running) since Fri 2026-02-20 09:00:00 UTC; 2h ago\n"
                    f" Main PID: {rng.randint(100, 2000)} ({service})\n"
                    "    Tasks: 1\n"
                    f"   Memory: {rng.randint(5, 50)}.0M\n"
                    f"   CGroup: /system.slice/{service}.service\n"
                ),
                "",
                0,
            )
        return (
            (
                "UNIT                            LOAD   ACTIVE SUB     DESCRIPTION\n"
                "ssh.service                     loaded active running OpenBSD Secure Shell server\n"
                "cron.service                    loaded active running Regular background program processing daemon\n"
            ),
            "",
            0,
        )
