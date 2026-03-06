from .base import Command


class CrontabCommand(Command):
    async def execute(self, args, input_data=""):
        cron_dir = "/var/spool/cron/crontabs"
        cron_file = f"{cron_dir}/{self.emulator.username}"

        if not self.fs.exists(cron_dir):
            self.fs.mkdir_p(cron_dir, owner="root")

        if "-l" in args:
            if not self.fs.exists(cron_file):
                return f"no crontab for {self.emulator.username}\n", "", 0
            return self.fs.get_content(cron_file), "", 0

        if "-r" in args:
            if self.fs.exists(cron_file):
                self.fs.remove(cron_file)
            return "", "", 0

        if "-e" in args:
            self.emulator.pending_input_callback = self._on_editor_input
            self.emulator.pending_input_prompt = (
                "(crontab) type DONE on a new line to save, CANCEL to abort > "
            )

            existing = ""
            if self.fs.exists(cron_file):
                existing = self.fs.get_content(cron_file)

            self._capture_lines = existing.splitlines() if existing else []
            prompt = "Entering crontab editor...\n"
            if self._capture_lines:
                prompt += "(Appending to existing crontab)\n"
            return prompt, "", 0

        files = [a for a in args if not a.startswith("-")]
        if files:
            target = self.emulator.resolve_path(files[0])
            if not self.fs.exists(target):
                return "", f"crontab: {files[0]}: No such file or directory\n", 1
            if self.fs.is_dir(target):
                return "", f"crontab: {files[0]}: Is a directory\n", 1

            content = self.fs.get_content(target)
            self.fs.mkfile(cron_file, content=content, owner=self.emulator.username)
            return "", "", 0

        return "crontab: usage error: file name must be specified for install.\n", "", 1

    async def _on_editor_input(self, line: str) -> tuple[str, str, int]:
        raw_line = line.strip()
        if raw_line == "CANCEL":
            return "crontab: edits aborted\n", "", 0

        if raw_line == "DONE":
            cron_dir = "/var/spool/cron/crontabs"
            cron_file = f"{cron_dir}/{self.emulator.username}"
            content = "\n".join(self._capture_lines) + "\n" if self._capture_lines else ""
            self.fs.mkfile(cron_file, content=content, owner=self.emulator.username)
            return "crontab: installing new crontab\n", "", 0

        self._capture_lines.append(line.rstrip("\n"))
        self.emulator.pending_input_callback = self._on_editor_input
        self.emulator.pending_input_prompt = "> "
        return "", "", 0
