import asyncio

from .base import Command


class PythonCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0.1)
        self._log_execution(args, input_data)

        if "-h" in args or "--help" in args:
            return self._handle_help()

        if "--version" in args or "-V" in args:
            return self._handle_version()

        if "-c" in args:
            return self._handle_one_liner(args)

        if len(args) > 0 and not args[0].startswith("-"):
            return self._handle_script_file(args)

        return self._start_interactive()

    def _log_execution(self, args: list[str], input_data: str):
        self._log_event(
            "python_execution_attempt",
            {"args": args, "input_len": len(input_data)},
        )

    def _handle_help(self) -> tuple[str, str, int]:
        return (
            "usage: python [option] ... [-c cmd | -m mod | file | -] [arg] ...\n"
            "Options and arguments (and corresponding environment variables):\n"
            "-c cmd : program passed in as string (terminates option list)\n",
            "",
            0,
        )

    def _handle_version(self) -> tuple[str, str, int]:
        return "Python 3.10.12\n", "", 0

    def _handle_one_liner(self, args: list[str]) -> tuple[str, str, int]:
        try:
            c_idx = args.index("-c")
            if c_idx + 1 < len(args):
                script = args[c_idx + 1]
                self._log_event(
                    "python_script_payload",
                    {"script": script},
                )
                return "", "", 0
            else:
                return (
                    "",
                    "Argument expected for the -c option\nusage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...\nTry `python -h' for more information.\n",
                    2,
                )
        except (ValueError, IndexError):
            return "", "", 0

    def _handle_script_file(self, args: list[str]) -> tuple[str, str, int]:
        target = self.emulator.resolve_path(args[0])
        if not self.fs.exists(target):
            return (
                "",
                f"python: can't open file '{args[0]}': [Errno 2] No such file or directory\n",
                2,
            )
        content = self.fs.get_content(target)
        if isinstance(content, bytes):
            content = content.decode("utf-8", "ignore")
        self._log_event(
            "python_file_run",
            {"file": args[0], "content": content},
        )
        return "", "", 0

    def _start_interactive(self) -> tuple[str, str, int]:
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
        if not cmd:
            self.emulator.pending_input_callback = self._on_input
            self.emulator.pending_input_prompt = ">>> "
            return "", "", 0

        if cmd in ("quit()", "exit()", "exit", "quit"):
            return "", "", 0

        # Log interactive python session lines
        self._log_event("python_repl_input", {"line": cmd})

        output = ""
        # Simple imitation of common Python errors/outputs
        if "print(" in cmd:
            try:
                output = cmd.split("print(")[1].split(")")[0].strip("'\"") + "\n"
            except Exception:
                output = ""
        elif cmd == "help":
            output = "Type help() for interactive help, or help(object) for help about object.\n"
        elif cmd:
            # Most common things in honeypot are import os; os.system(...)
            # We silently acknowledge them
            output = ""

        self.emulator.pending_input_callback = self._on_input
        self.emulator.pending_input_prompt = ">>> "
        return output, "", 0
