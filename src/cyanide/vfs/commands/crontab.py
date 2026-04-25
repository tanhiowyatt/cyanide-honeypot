import asyncio
import logging

from .base import Command


class CrontabCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the crontab command."""
        cron_dir = "/var/spool/cron/crontabs"
        cron_file = f"{cron_dir}/{self.emulator.username}"

        if not self.fs.exists(cron_dir):
            self.fs.mkdir_p(cron_dir, owner="root")

        if "-l" in args:
            return self._handle_list(cron_file)

        if "-r" in args:
            return self._handle_remove(cron_file)

        if "-e" in args:
            return self._handle_edit(cron_file)

        return self._handle_install(args, cron_file)

    def _handle_list(self, cron_file: str) -> tuple[str, str, int]:
        """Handle listing the crontab."""
        if not self.fs.exists(cron_file):
            return f"no crontab for {self.emulator.username}\n", "", 0
        return self.fs.get_content(cron_file), "", 0

    def _handle_remove(self, cron_file: str) -> tuple[str, str, int]:
        """Handle removing the crontab."""
        if self.fs.exists(cron_file):
            self.fs.remove(cron_file)
        return "", "", 0

    def _handle_edit(self, cron_file: str) -> tuple[str, str, int]:
        """Handle editing the crontab."""
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

    def _handle_install(self, args: list[str], cron_file: str) -> tuple[str, str, int]:
        """Handle installing a crontab from a file."""
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return (
                "crontab: usage error: file name must be specified for install.\n",
                "",
                1,
            )

        target = self.emulator.resolve_path(files[0])
        if not self.fs.exists(target):
            return "", f"crontab: {files[0]}: No such file or directory\n", 1
        if self.fs.is_dir(target):
            return "", f"crontab: {files[0]}: Is a directory\n", 1

        content = self.fs.get_content(target)
        self.fs.mkfile(cron_file, content=content, owner=self.emulator.username)
        return "", "", 0

    def _on_editor_input(self, line: str) -> tuple[str, str, int]:
        raw_line = line.strip()
        if raw_line == "CANCEL":
            return "crontab: edits aborted\n", "", 0

        if raw_line == "DONE":
            cron_dir = "/var/spool/cron/crontabs"
            cron_file = f"{cron_dir}/{self.emulator.username}"
            content = "\n".join(self._capture_lines) + "\n" if self._capture_lines else ""
            self.fs.mkfile(cron_file, content=content, owner=self.emulator.username)

            # Initiate background simulation of cron jobs
            if not hasattr(self, "_background_tasks"):
                self._background_tasks: set[asyncio.Task] = set()  # type: ignore[type-arg]
            for entry in self._capture_lines:
                if entry and not entry.startswith("#"):
                    task = asyncio.create_task(self._schedule_cron_job(entry))
                    self._background_tasks.add(task)
                    task.add_done_callback(self._background_tasks.discard)

            return "crontab: installing new crontab\n", "", 0

        self._capture_lines.append(line.rstrip("\n"))
        self.emulator.pending_input_callback = self._on_editor_input
        self.emulator.pending_input_prompt = "> "
        return "", "", 0

    async def _schedule_cron_job(self, entry: str):
        """Parse cron line and schedule simulated execution."""
        parts = entry.split()
        if len(parts) < 6:
            return

        cmd_str = " ".join(parts[5:])

        # ML Analysis Check
        if self.emulator.analytics and self.emulator.analytics.is_malicious(cmd_str):
            self._log_event(
                "cron_simulation_blocked",
                {"command": cmd_str, "reason": "ML flagged as malicious"},
            )
            return

        # Simulate delay (realistic for cron)
        await asyncio.sleep(5)

        self._log_event("cron_simulation_start", {"command": cmd_str})

        # Basic simulation: handle redirection like echo "x" >> file
        try:
            # We use the shell emulator itself to execute the command!
            # This is the most realistic way because it uses our existing VFS/Redirection logic.
            await self.emulator.execute(cmd_str)
        except Exception as e:
            logging.error(f"Cron simulation failed for '{cmd_str}': {e}")
