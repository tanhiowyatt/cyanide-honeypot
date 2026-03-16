import argparse

from .base import Command


class GrepCommand(Command):
    # Function 236: Executes the 'grep' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="grep", add_help=False)
        parser.add_argument("-i", "--ignore-case", action="store_true")
        parser.add_argument("-v", "--invert-match", action="store_true")
        parser.add_argument("pattern", nargs="?")
        parser.add_argument("files", nargs="*")

        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1

        pattern = parsed.pattern
        if not pattern:
            return "", "Usage: grep [OPTION]... PATTERN [FILE]...\n", 2

        files = parsed.files
        ignore_case = parsed.ignore_case
        invert_match = parsed.invert_match
        recursive = "-r" in args or "-R" in args

        lines = []
        if not files:
            lines = input_data.splitlines(keepends=True)
        else:
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
                    content = self.fs.get_content(path)
                    lines.extend(content.splitlines(keepends=True))
                elif self.fs.is_dir(path):
                    return "", f"grep: {f}: Is a directory\n", 2

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

        rc = 0 if output else 1
        return output, "", rc

    # Function 237: Performs operations related to get recursive files.
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
