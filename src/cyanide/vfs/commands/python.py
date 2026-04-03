import asyncio

from .base import Command


class PythonCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if "-c" in args:
            return "", "", 0

        if "--version" in args or "-V" in args:
            return "Python 3.10.12\n", "", 0

        if len(args) > 0 and not args[0].startswith("-"):
            target = self.emulator.resolve_path(args[0])
            if not self.fs.exists(target):
                return (
                    "",
                    f"python: can't open file '{args[0]}': [Errno 2] No such file or directory\n",
                    2,
                )
            return "", "", 0

        self.emulator.pending_input_callback = self._on_input
        self.emulator.pending_input_prompt = ">>> "

        return (
            (
                "Python 3.10.12 (main, Jun 11 2023, 05:26:28) [GCC 11.4.0] on linux\n"
                'Type "help", "copyright", "credits" or "license" for more information.\n'
            ),
            "",
            0,
        )

    def _on_input(self, line: str) -> tuple[str, str, int]:
        cmd = line.strip()
        if cmd in ("quit()", "exit()", "exit", "quit"):
            return "", "", 0

        output = ""
        if cmd == "help":
            output = "Type help() for interactive help, or help(object) for help about object.\n"
        elif cmd == "help()":
            output = "Welcome to Python 3.10's help utility!\n"
        elif cmd == "copyright":
            output = "Copyright (c) 2001-2023 Python Software Foundation.\nAll Rights Reserved.\n"
        elif cmd:
            if cmd.isalpha() and cmd not in ("print", "import", "def", "class"):
                output = f"Traceback (most recent call last):\n  File \"<stdin>\", line 1, in <module>\nNameError: name '{cmd}' is not defined\n"

        self.emulator.pending_input_callback = self._on_input
        self.emulator.pending_input_prompt = ">>> "
        return output, "", 0
