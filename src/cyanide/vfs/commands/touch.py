from .base import Command


class TouchCommand(Command):
    # Function 271: Executes the 'touch' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        if not args:
            return "", "touch: missing file operand\n", 1

        for arg in args:
            if arg.startswith("-"):
                continue

            path = self.emulator.resolve_path(arg)
            if self.fs.exists(path):
                pass
            else:
                if self.fs.mkfile(path, content="", owner=self.username) is None:
                    return (
                        "",
                        f"touch: cannot touch '{arg}': No such file or directory\n",
                        1,
                    )

        return "", "", 0
