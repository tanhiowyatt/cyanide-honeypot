import argparse
import re

from .base import Command


class AwkCommand(Command):
    """
    Basic awk emulator for honeypot command chains.
    Supports -F and simple {print $N}.
    """

    # Function 205: Executes the 'awk' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="awk", add_help=False)
        parser.add_argument("-F", "--field-separator", default=" ")
        parser.add_argument("program", nargs="?")
        parser.add_argument("files", nargs="*")

        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1

        separator = parsed.field_separator
        program = parsed.program
        files = parsed.files

        if not program:
            return "", "awk: no program specified\n", 1

        print_match = re.search(r"\{print\s+(.*)\}", program)
        if not print_match:
            return "", "", 0

        fields_to_print = []
        raw_fields = [f.strip() for f in print_match.group(1).split(",")]
        for f in raw_fields:
            if f.startswith("$"):
                try:
                    fields_to_print.append(int(f[1:]))
                except ValueError:
                    pass

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
                    return "", f"awk: {f}: Is a directory\n", 2

        output_lines = []
        for line in lines:
            if not line.strip():
                continue

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

            if row_output:
                output_lines.append(" ".join(row_output))

        return "\n".join(output_lines) + ("\n" if output_lines else ""), "", 0
