from .base import Command


class ChmodCommand(Command):
    async def execute(self, args, input_data=""):
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

            # Simple mock: if numeric, update node.perm
            if mode.isdigit():
                # ... simplified
                node.perm = "-rwxrwxrwx" if mode == "777" else node.perm
            else:
                # e.g. +x
                if "+x" in mode:
                    p = list(node.perm)
                    p[3] = "x"
                    p[6] = "x"
                    p[9] = "x"
                    node.perm = "".join(p)

        return "", "", 0
