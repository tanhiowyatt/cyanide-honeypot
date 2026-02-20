import argparse
from pathlib import PurePosixPath

from cyanide.vfs.nodes import Directory

from .base import Command


class MkdirCommand(Command):
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

            # Simplified logic for -p
            if parsed.parents:
                # Recursive creation
                parts = [p for p in resolved.split("/") if p]
                current = self.fs.root
                for part in parts:
                    child = current.get_child(part)
                    if not child:
                        child = Directory(
                            part,
                            parent=current,
                            owner=self.username,
                            group=self.username,
                        )
                        current.add_child(child)
                    current = child
            else:
                parent_path = str(PurePosixPath(resolved).parent)
                dirname = PurePosixPath(resolved).name
                parent = self.fs.get_node(parent_path)

                if not parent or not isinstance(parent, Directory):
                    return (
                        "",
                        f"mkdir: cannot create directory '{path_str}': No such file or directory\n",
                        1,
                    )

                new_dir = Directory(
                    dirname, parent=parent, owner=self.username, group=self.username
                )
                parent.add_child(new_dir)

        return "", "", 0
