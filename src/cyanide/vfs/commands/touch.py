from pathlib import PurePosixPath

from cyanide.vfs.nodes import Directory, File

from .base import Command


class TouchCommand(Command):
    async def execute(self, args, input_data=""):
        if not args:
            return "", "touch: missing file operand\n", 1

        for arg in args:
            # Ignore flags for now
            if arg.startswith("-"):
                continue

            path = self.emulator.resolve_path(arg)
            if self.fs.exists(path):
                # Update timestamp (fake)
                pass
            else:
                # Create empty file
                parent_path = str(PurePosixPath(path).parent)
                filename = PurePosixPath(path).name

                parent = self.fs.get_node(parent_path)
                if isinstance(parent, Directory):
                    new_file = File(
                        filename,
                        parent=parent,
                        content="",
                        owner=self.username,
                        group=self.username,
                    )
                    parent.add_child(new_file)
                else:
                    return (
                        "",
                        f"touch: cannot touch '{arg}': No such file or directory\n",
                        1,
                    )

        return "", "", 0
