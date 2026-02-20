from .base import Command


class CrontabCommand(Command):
    async def execute(self, args, input_data=""):
        if "-l" in args:
            return (
                (
                    "# m h  dom mon dow   command\n"
                    "*/5 * * * * /usr/local/bin/check_status.sh > /dev/null 2>&1\n"
                    "0 0 * * * /usr/bin/backup_logs.sh\n"
                ),
                "",
                0,
            )
        return "no crontab for " + self.emulator.username + "\n", "", 0
