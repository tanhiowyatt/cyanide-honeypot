import argparse
import asyncio
from pathlib import PurePosixPath

from .base import Command


class MkdirCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)

        parser = argparse.ArgumentParser(prog="mkdir", add_help=False)
        parser.add_argument("-p", "--parents", action="store_true")
        parser.add_argument("path", nargs="+")

        try:
            parsed, unknown = parser.parse_known_args(args)

            if self.emulator.logger:
                self.emulator.logger.log_event(
                    self.emulator.session_id,
                    "mkdir_unknown_args",
                    {
                        "src_ip": self.emulator.src_ip,
                        "path": parsed.path,
                        "unknown_args": unknown,
                        "full_cmd": " ".join(args),
                    },
                )

        except SystemExit:
            if self.emulator.logger:
                self.emulator.logger.log_event(
                    self.emulator.session_id,
                    "mkdir_parse_fail",
                    {"src_ip": self.emulator.src_ip, "full_cmd": " ".join(args)},
                )
            return "", "mkdir: argument error\n", 2

        if not hasattr(parsed, "path") or not parsed.path:
            return "", "mkdir: missing operand\n", 1

        for path_str in parsed.path:
            resolved = self.emulator.resolve_path(path_str)

            if self.fs.exists(resolved):
                return "", f"mkdir: cannot create directory '{path_str}': File exists\n", 1

            if parsed.parents:
                self.fs.mkdir_p(resolved, owner=self.username)
            else:
                parent_path = str(PurePosixPath(resolved).parent)
                if not self.fs.exists(parent_path) or not self.fs.is_dir(parent_path):
                    return (
                        "",
                        f"mkdir: cannot create directory '{path_str}': No such file or directory\n",
                        1,
                    )
                self.fs.mkdir_p(resolved, owner=self.username)

            if self.emulator.logger:
                self.emulator.logger.log_event(
                    self.emulator.session_id,
                    "mkdir_success",
                    {"path": resolved, "parents": parsed.parents},
                )

        return "", "", 0
