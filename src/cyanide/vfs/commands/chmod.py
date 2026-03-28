import asyncio

from .base import Command


class ChmodCommand(Command):
    # Function 218: Executes the 'chmod' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if len(args) < 2:
            return "", "chmod: missing operand\n", 1

        mode = args[0]
        targets = args[1:]

        for target in targets:
            path = self.emulator.resolve_path(target)
            node = self.fs.get_node(path)
            if not node:
                return (
                    "",
                    f"chmod: cannot access '{target}': No such file or directory\n",
                    1,
                )

            if mode.isdigit():
                node.perm = "-rwxrwxrwx" if mode == "777" else node.perm
            else:
                if "+x" in mode:
                    p = list(node.perm)
                    p[3] = "x"
                    p[6] = "x"
                    p[9] = "x"
                    node.perm = "".join(p)

        return "", "", 0
