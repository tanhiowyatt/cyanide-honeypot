import asyncio

from .base import Command


class FindCommand(Command):
    # Function 231: Executes the 'find' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if not args:
            return ".\n", "", 0

        start_path = self.emulator.resolve_path(args[0])
        if not self.fs.exists(start_path):
            return "", f"find: '{args[0]}': No such file or directory\n", 1

        pattern = None
        if "-name" in args:
            idx = args.index("-name")
            if idx + 1 < len(args):
                pattern = args[idx + 1].strip("'\"").replace("*", "")

        all_paths = self._walk(start_path)
        if pattern:
            all_paths = [p for p in all_paths if pattern in p]

        return "\n".join(all_paths) + ("\n" if all_paths else ""), "", 0

    # Function 232: Performs operations related to walk.
    def _walk(self, path):
        paths = [path]
        node = self.fs.get_node(path)
        if hasattr(node, "children"):
            for child in node.children.values():
                child_path = f"{path}/{child.name}".replace("//", "/")
                paths.extend(self._walk(child_path))
        return paths
