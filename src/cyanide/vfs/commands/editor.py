from typing import List

from .base import Command


class EditorCommand(Command):
    """Simplified text editor for low-latency command emulation."""

    def __init__(self, emulator):
        super().__init__(emulator)
        self.target_file = ""
        self._capture_lines: List[str] = []

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        if not args:
            return "", "No filename provided.\n", 1

        self.target_file = self.emulator.resolve_path(args[0])

        existing = ""
        if self.fs.exists(self.target_file):
            if self.fs.is_dir(self.target_file):
                return "", f'"{args[0]}" is a directory\n', 1
            existing = self.fs.get_content(self.target_file)

        self._capture_lines = existing.splitlines() if existing else []
        self.emulator.pending_input_callback = self._on_input
        self.emulator.pending_input_prompt = "editor> "

        prompt = f"Entering editor for {args[0]}.\nType :wq or ^X on a new line to save and exit, :q! or ^C to abort.\n"
        if self._capture_lines:
            prompt += f"(File has {len(self._capture_lines)} existing lines)\n"

        return prompt, "", 0

    def _on_input(self, line: str) -> tuple[str, str, int]:
        raw_line = line.strip()

        if raw_line in [":wq", "wq", "^X", ":w"]:
            content = "\n".join(self._capture_lines) + "\n" if self._capture_lines else ""
            self.fs.mkfile(self.target_file, content=content, owner=self.emulator.username)
            if raw_line == ":w":
                self.emulator.pending_input_callback = self._on_input
                self.emulator.pending_input_prompt = "editor> "
                return f'"{self.target_file}" written\n', "", 0
            return f'"{self.target_file}" written, exit.\n', "", 0

        if raw_line in [":q!", "q!", "^C", ":q"]:
            return "Aborted.\n", "", 0

        self._capture_lines.append(line.rstrip("\n"))
        self.emulator.pending_input_callback = self._on_input
        self.emulator.pending_input_prompt = "editor> "
        return "", "", 0


class NanoCommand(EditorCommand):
    pass


class VimCommand(EditorCommand):
    pass
