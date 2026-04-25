import asyncio

from .base import Command


class GccCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0.5)  # Simulate compilation time

        if not args:
            return "", "gcc: fatal error: no input files\ncompilation terminated.\n", 1

        if "--version" in args:
            return (
                "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\nCopyright (C) 2021 Free Software Foundation, Inc.\n",
                "",
                0,
            )

        # Look for -o <output_file>
        output_file = "a.out"
        if "-o" in args:
            try:
                o_idx = args.index("-o")
                if o_idx + 1 < len(args):
                    output_file = args[o_idx + 1]
            except Exception:
                pass

        # Check if input files exist (rudimentary)
        sources = [a for a in args if a.endswith(".c") or a.endswith(".cpp")]
        for src in sources:
            if not self.fs.exists(self.emulator.resolve_path(src)):
                return (
                    "",
                    f"gcc: error: {src}: No such file or directory\nfatal error: no input files\ncompilation terminated.\n",
                    1,
                )

        # Simulate creation of the binary
        if output_file:
            path = self.emulator.resolve_path(output_file)
            # Create a dummy ELF-like binary
            self.fs.mkfile(
                path,
                content=b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                perm="-rwxr-xr-x",
            )

        self._log_event(
            "gcc_compilation",
            {"args": args, "output": output_file},
        )

        return "", "", 0
