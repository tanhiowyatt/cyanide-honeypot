import asyncio

from .base import Command


class VisudoCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0.1)
        if self.emulator.username != "root":
            return (
                "",
                "visudo: /etc/sudoers: Permission denied\n",
                1,
            )

        self.emulator.pending_input_callback = self._on_editor_input
        self.emulator.pending_input_prompt = (
            "(visudo) type DONE on a new line to save, CANCEL to abort > "
        )

        existing = ""
        target_file = "/etc/sudoers"
        if self.fs.exists(target_file):
            existing = self.fs.get_content(target_file)
            if isinstance(existing, bytes):
                existing = existing.decode("utf-8", "ignore")

        self._capture_lines = existing.splitlines() if existing else []
        prompt = "visudo: editing /etc/sudoers...\n"
        return prompt, "", 0

    def _on_editor_input(self, line: str) -> tuple[str, str, int]:
        raw_line = line.strip()
        if raw_line == "CANCEL":
            return "visudo: edits aborted\n", "", 0

        if raw_line == "DONE":
            target_file = "/etc/sudoers"
            content = "\n".join(self._capture_lines) + "\n" if self._capture_lines else ""
            self.fs.mkfile(target_file, content=content, owner="root")
            self._log_event("sudoers_modified", {"content": content})
            return "visudo: /etc/sudoers: success\n", "", 0

        self._capture_lines.append(line.rstrip("\n"))
        self.emulator.pending_input_callback = self._on_editor_input
        self.emulator.pending_input_prompt = "> "
        return "", "", 0
