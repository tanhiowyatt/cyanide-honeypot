import asyncio

from cyanide.vfs.nodes import Directory

from .base import Command


class RmCommand(Command):

    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        recursive = "-r" in args or "-rf" in args or "-R" in args
        force = "-f" in args or "-rf" in args

        targets = [a for a in args if not a.startswith("-")]

        if not targets and not force:
            return "", "rm: missing operand\n", 1

        for arg in targets:
            path = self.emulator.resolve_path(arg)
            node = self.fs.get_node(path)

            if not node:
                if not force:
                    return (
                        "",
                        f"rm: cannot remove '{arg}': No such file or directory\n",
                        1,
                    )
                continue

            if isinstance(node, Directory) and not recursive:
                return "", f"rm: cannot remove '{arg}': Is a directory\n", 1

            self.fs.remove(path)

        return "", "", 0
