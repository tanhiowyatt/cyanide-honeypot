import argparse
import asyncio

from .base import Command


class TailCommand(Command):
    # Function 270: Executes the 'tail' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)

        parser = argparse.ArgumentParser(prog="tail", add_help=False)
        parser.add_argument("-n", "--lines", type=int, default=10)
        parser.add_argument("files", nargs="*")

        try:
            parsed, unknown = parser.parse_known_args(args)

            # Логируем мусорные аргументы для ML
            if unknown and self.emulator.logger:
                self.emulator.logger.log_event(
                    self.emulator.session_id,
                    "tail_unknown_args",
                    {
                        "src_ip": self.emulator.src_ip,
                        "files": parsed.files,
                        "unknown_args": unknown,  # [-f --follow --pwned]
                        "full_cmd": " ".join(args),
                    },
                )

        except SystemExit:
            # Логируем recon attempts для ML
            if self.emulator.logger:
                self.emulator.logger.log_event(
                    self.emulator.session_id,
                    "tail_parse_fail",
                    {"src_ip": self.emulator.src_ip, "full_cmd": " ".join(args)},
                )
            return "", "tail: argument error\n", 2

        count = parsed.lines
        files = parsed.files
        lines = []

        if not files:
            lines = input_data.splitlines(keepends=True)
        else:
            path = self.emulator.resolve_path(files[0])
            if self.fs.is_file(path):
                lines = self.fs.get_content(path).splitlines(keepends=True)

        return "".join(lines[-count:]), "", 0
