import argparse
from pathlib import PurePosixPath

from .base import Command


class MkdirCommand(Command):
    # Function 250: Executes the 'mkdir' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="mkdir", add_help=False)
        parser.add_argument("-p", "--parents", action="store_true")
        parser.add_argument("path", nargs="+")

        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1

        for path_str in parsed.path:
            resolved = self.emulator.resolve_path(path_str)

            if self.fs.exists(resolved):
                return (
                    "",
                    f"mkdir: cannot create directory '{path_str}': File exists\n",
                    1,
                )

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

        return "", "", 0
