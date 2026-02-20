import argparse

from .base import Command


class HeadCommand(Command):
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="head", add_help=False)
        parser.add_argument("-n", "--lines", type=int, default=10)
        parser.add_argument("files", nargs="*")

        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1

        count = parsed.lines
        files = parsed.files

        lines = []
        if not files:
            lines = input_data.splitlines(keepends=True)
        else:
            path = self.emulator.resolve_path(files[0])
            if self.fs.is_file(path):
                lines = self.fs.get_content(path).splitlines(keepends=True)

        return "".join(lines[:count]), "", 0
