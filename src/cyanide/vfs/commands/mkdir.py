import argparse
import asyncio
from pathlib import PurePosixPath

from .base import Command


class MkdirCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        parser = self._prepare_parser()

        try:
            parsed, unknown = parser.parse_known_args(args)
            if unknown:
                self._log_event(
                    "mkdir_unknown_args",
                    {"path": parsed.path, "unknown_args": unknown, "full_cmd": " ".join(args)},
                )
        except SystemExit:
            self._log_event("mkdir_parse_fail", {"full_cmd": " ".join(args)})
            raise

        if not getattr(parsed, "path", None):
            return "", "mkdir: missing operand\n", 1

        return self._execute_mkdir_loop(parsed)

    def _prepare_parser(self):
        parser = argparse.ArgumentParser(prog="mkdir", add_help=False)
        parser.add_argument("-p", "--parents", action="store_true")
        parser.add_argument("path", nargs="+")
        return parser

    def _log_event(self, event_type, data):
        if self.emulator.logger:
            data["src_ip"] = self.emulator.src_ip
            self.emulator.logger.log_event(self.emulator.session_id, event_type, data)

    def _execute_mkdir_loop(self, parsed):
        for path_str in parsed.path:
            resolved = self.emulator.resolve_path(path_str)
            if self.fs.exists(resolved):
                return "", f"mkdir: cannot create directory '{path_str}': File exists\n", 1

            error_msg, code = self._do_mkdir(resolved, path_str, parsed.parents)
            if code != 0:
                return "", error_msg, code

            self._log_event("mkdir_success", {"path": resolved, "parents": parsed.parents})
        return "", "", 0

    def _do_mkdir(self, resolved, original_path, parents):
        if parents:
            self.fs.mkdir_p(resolved, owner=self.username)
        else:
            parent_path = str(PurePosixPath(resolved).parent)
            if not self.fs.exists(parent_path) or not self.fs.is_dir(parent_path):
                return (
                    f"mkdir: cannot create directory '{original_path}': No such file or directory\n",
                    1,
                )
            self.fs.mkdir_p(resolved, owner=self.username)
        return "", 0
