import argparse
import asyncio

from .base import Command


class TailCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)

        parser = argparse.ArgumentParser(prog="tail", add_help=False)
        parser.add_argument("-n", "--lines", type=int, default=10)
        parser.add_argument("files", nargs="*")

        try:
            parsed, unknown = parser.parse_known_args(args)

            if unknown:
                self._log_event(
                    "tail_unknown_args",
                    {
                        "files": parsed.files,
                        "unknown_args": unknown,
                        "full_cmd": " ".join(args),
                    },
                )

        except SystemExit:
            self._log_event(
                "tail_parse_fail",
                {"full_cmd": " ".join(args)},
            )
            raise

        count = parsed.lines
        files = parsed.files
        lines = []

        if not files:
            lines = input_data.splitlines(keepends=True)
        else:
            path = self.emulator.resolve_path(files[0])
            if self.fs.is_dir(path):
                return "", f"tail: error reading '{files[0]}': Is a directory\n", 1
            if self.fs.is_file(path):
                lines = self.get_content_str(path).splitlines(keepends=True)
            else:
                return (
                    "",
                    f"tail: cannot open '{files[0]}' for reading: No such file or directory\n",
                    1,
                )

        return "".join(lines[-count:]), "", 0
