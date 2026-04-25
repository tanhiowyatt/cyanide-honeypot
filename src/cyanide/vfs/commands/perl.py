import asyncio

from .base import Command


class PerlCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0.1)
        self._log_execution(args, input_data)

        if "-v" in args:
            return self._handle_version()

        if "-e" in args:
            return self._handle_one_liner(args)

        if len(args) > 0 and not args[0].startswith("-"):
            return self._handle_script_file(args)

        return "", "", 0

    def _log_execution(self, args: list[str], input_data: str) -> None:
        self._log_event(
            "perl_execution_attempt",
            {"args": args, "input_len": len(input_data)},
        )

    def _handle_version(self) -> tuple[str, str, int]:
        return (
            "This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi\n",
            "",
            0,
        )

    def _handle_one_liner(self, args: list[str]) -> tuple[str, str, int]:
        try:
            e_idx = args.index("-e")
            if e_idx + 1 < len(args):
                script = args[e_idx + 1]
                self._log_event(
                    "perl_script_payload",
                    {"script": script},
                )
                return "", "", 0
            else:
                return "", "perl: -e requires an argument.\n", 1
        except (ValueError, IndexError):
            return "", "", 0

    def _handle_script_file(self, args: list[str]) -> tuple[str, str, int]:
        target = self.emulator.resolve_path(args[0])
        if not self.fs.exists(target):
            return (
                "",
                f'Can\'t open perl script "{args[0]}": No such file or directory\n',
                2,
            )

        content = self.fs.get_content(target)
        if isinstance(content, bytes):
            content = content.decode("utf-8", "ignore")
        self._log_event(
            "perl_file_run",
            {"file": args[0], "content": content},
        )
        return "", "", 0
