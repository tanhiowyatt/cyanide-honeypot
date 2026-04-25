import argparse
import asyncio

from .base import Command


class GrepCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        """Execute the grep command."""
        parsed, recursive = self._parse_grep_args(args)
        if not parsed.pattern:
            return "", "Usage: grep [OPTION]... PATTERN [FILE]...\n", 2

        try:
            lines, error_msg = self._collect_lines(parsed.files, recursive, input_data)
        except Exception as e:
            return "", f"grep: {str(e)}\n", 2

        if error_msg:
            return "", error_msg, 2

        output = self._filter_lines(lines, parsed.pattern, parsed.ignore_case, parsed.invert_match)

        rc = 0 if output else 1
        return output, "", rc

    def _parse_grep_args(self, args):
        """Parse grep arguments and return (parsed_args, recursive_flag)."""
        parser = argparse.ArgumentParser(prog="grep", add_help=False)
        parser.add_argument("-i", "--ignore-case", action="store_true")
        parser.add_argument("-v", "--invert-match", action="store_true")
        parser.add_argument("pattern", nargs="?")
        parser.add_argument("files", nargs="*")

        try:
            parsed, unknown = parser.parse_known_args(args)

            if unknown:
                self._log_event(
                    "grep_unknown_args",
                    {
                        "pattern": parsed.pattern,
                        "unknown_args": unknown,
                        "full_cmd": " ".join(args),
                    },
                )

        except SystemExit:
            self._log_event(
                "grep_parse_fail",
                {"full_cmd": " ".join(args)},
            )
            raise

        recursive = "-r" in args or "-R" in args
        return parsed, recursive

    def _collect_lines(self, files, recursive, input_data):
        """Collect lines from files or input data."""
        lines = []
        if not files:
            return input_data.splitlines(keepends=True), None

        for f in files:
            path = self.emulator.resolve_path(f)
            if recursive and self.fs.is_dir(path):
                all_files = self._get_recursive_files(path)
                for filepath in all_files:
                    content = self.fs.get_content(filepath)
                    lines.extend(
                        [f"{filepath}:{line}" for line in content.splitlines(keepends=True)]
                    )
            elif self.fs.is_file(path):
                content = self.get_content_str(path)
                lines.extend(content.splitlines(keepends=True))
            elif self.fs.is_dir(path):
                return [], f"grep: {f}: Is a directory\n"
            else:
                return [], f"grep: {f}: No such file or directory\n"

        return lines, None

    def _filter_lines(self, lines, pattern, ignore_case, invert_match):
        """Filter lines based on the pattern and flags."""
        output = ""
        search_pattern = pattern.lower() if ignore_case else pattern

        for line in lines:
            search_line = line.lower() if ignore_case else line
            match = search_pattern in search_line

            if invert_match:
                if not match:
                    output += line
            else:
                if match:
                    output += line
        return output

    def _get_recursive_files(self, path):
        """Helper to find all files recursively."""
        files = []
        node = self.fs.get_node(path)
        if hasattr(node, "children"):
            for child in node.children.values():
                child_path = f"{path}/{child.name}".replace("//", "/")
                if self.fs.is_file(child_path):
                    files.append(child_path)
                elif self.fs.is_dir(child_path):
                    files.extend(self._get_recursive_files(child_path))
        return files
