import posixpath

from .base import Command


class EditorCommand(Command):
    """Mock text editors (vi, nano, etc)."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        if not args:
            return "", "No filename provided.\n", 1

        self.target_file = self.emulator.resolve_path(args[0])

        existing = ""
        if self.fs.exists(self.target_file):
            if self.fs.is_dir(self.target_file):
                return "", f'"{args[0]}" is a directory\n', 1
            existing = self.fs.get_content(self.target_file)

        self.emulator.pending_input_callback = self._on_input
        self.emulator.pending_input_prompt = ""
        self._capture_lines = existing.splitlines() if existing else []

        prompt = f"Entering editor for {args[0]}.\nType :wq or ^X on a new line to save and exit, :q! or ^C to abort.\n"
        if self._capture_lines:
            prompt += "(File has existing content, new lines will be appended)\n"

        return prompt, "", 0

    async def _on_input(self, line: str) -> tuple[str, str, int]:
        stop_save = [":wq", "^X", "wq"]
        stop_abort = [":q!", "^C", "q!", ":q"]

        raw_line = line.strip()
        if raw_line in stop_save:
            parent = posixpath.dirname(self.target_file)
            if parent != "/" and not self.fs.exists(parent):
                self.fs.mkdir_p(parent, owner=self.emulator.username)

            content = "\n".join(self._capture_lines) + "\n" if self._capture_lines else ""
            self.fs.mkfile(self.target_file, content=content, owner=self.emulator.username)
            return f'"{self.target_file}" written\n', "", 0

        if raw_line in stop_abort:
            return "Aborted.\n", "", 0

        self._capture_lines.append(line.rstrip("\n"))
        self.emulator.pending_input_callback = self._on_input
        self.emulator.pending_input_prompt = ""
        return "", "", 0
