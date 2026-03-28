import asyncio

from .base import Command


class MvCommand(Command):
    # Function 251: Executes the 'mv' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if len(args) < 2:
            return "", "mv: missing file operand\n", 1

        clean_args = [a for a in args if not a.startswith("-")]
        if len(clean_args) < 2:
            return "", "mv: missing destination file operand\n", 1

        dest_str = clean_args[-1]
        sources = clean_args[:-1]

        dest_path = self.emulator.resolve_path(dest_str)

        for src_str in sources:
            src_path = self.emulator.resolve_path(src_str)

            if not self.fs.exists(src_path):
                return (
                    "",
                    f"mv: cannot stat '{src_str}': No such file or directory\n",
                    1,
                )

            if not self.fs.move(src_path, dest_path):
                return (
                    "",
                    f"mv: cannot move '{src_str}' to '{dest_str}': No such file or directory\n",
                    1,
                )

        return "", "", 0
