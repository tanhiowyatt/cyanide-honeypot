from .base import Command


class PythonCommand(Command):
    async def execute(self, args, input_data=""):
        if "-c" in args:
            # Common for reverse shells
            return "", "", 0
        if "--version" in args or "-V" in args:
            return "Python 3.10.12\n", "", 0
        return (
            (
                "Python 3.10.12 (main, Jun 11 2023, 05:26:28) [GCC 11.4.0] on linux\n"
                'Type "help", "copyright", "credits" or "license" for more information.\n'
                ">>> "
            ),
            "",
            0,
        )
