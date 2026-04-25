import argparse
import asyncio
import re
from typing import Optional

from .base import Command


class AwkCommand(Command):
    """
    Basic awk emulator for honeypot command chains.
    Supports -F and simple {print $N}.
    """

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the awk command."""
        parsed, rc = self._parse_awk_args(args)
        if rc != 0 or not parsed:
            return "", "awk: argument error\n" if rc != 0 else "", rc

        if not parsed.program:
            return "", "awk: no program specified\n", 1

        fields_to_print = self._get_fields_to_print(parsed.program)
        if not fields_to_print:
            return "", "", 0

        lines, err_res = self._get_input_lines(parsed.files, input_data)
        if err_res:
            return err_res

        output_lines = []
        for line in lines:
            processed = self._process_line(line, parsed.field_separator, fields_to_print)
            if processed:
                output_lines.append(processed)

        result = "\n".join(output_lines)
        return result + ("\n" if output_lines else ""), "", 0

    def _parse_awk_args(self, args: list[str]) -> tuple[Optional[argparse.Namespace], int]:
        """Parse awk arguments."""
        parser = argparse.ArgumentParser(prog="awk", add_help=False)
        parser.add_argument("-F", "--field-separator", default=" ")
        parser.add_argument("program", nargs="?")
        parser.add_argument("files", nargs="*")

        try:
            parsed, unknown = parser.parse_known_args(args)

            if unknown:
                self._log_event(
                    "awk_unknown_args",
                    {
                        "program": parsed.program,
                        "unknown_args": unknown,
                        "full_cmd": " ".join(args),
                    },
                )

            return parsed, 0
        except SystemExit:
            self._log_event(
                "awk_parse_fail",
                {"full_cmd": " ".join(args)},
            )
            raise

    def _get_fields_to_print(self, program: str) -> list[int]:
        """Parse the awk program to find which fields to print."""
        print_match = re.search(r"\{print\s+([^}\s][^}]*)\}", program)
        if not print_match:
            return []

        fields_to_print = []
        raw_fields = [f.strip() for f in print_match.group(1).split(",")]
        for f in raw_fields:
            if f.startswith("$"):
                try:
                    fields_to_print.append(int(f[1:]))
                except ValueError:
                    pass
        return fields_to_print

    def _get_input_lines(
        self, files: list[str], input_data: str
    ) -> tuple[list[str], Optional[tuple[str, str, int]]]:
        """Gather all lines of input from files or stdin."""
        lines = []
        if not files:
            lines = input_data.splitlines()
        else:
            for f in files:
                path = self.emulator.resolve_path(f)
                if self.fs.is_file(path):
                    content = self.fs.get_content(path)
                    lines.extend(content.splitlines())
                elif self.fs.is_dir(path):
                    return [], ("", f"awk: {f}: Is a directory\n", 2)
        return lines, None

    def _process_line(self, line: str, separator: str, fields_to_print: list[int]) -> Optional[str]:
        """Process a single line and extract requested fields."""
        if not line.strip():
            return None

        if separator == " ":
            fields = line.split()
        else:
            fields = line.split(separator)

        row_output = []
        for field_idx in fields_to_print:
            if field_idx == 0:
                row_output.append(line)
            elif 0 < field_idx <= len(fields):
                row_output.append(fields[field_idx - 1])
            else:
                row_output.append("")

        return " ".join(row_output) if row_output else None
