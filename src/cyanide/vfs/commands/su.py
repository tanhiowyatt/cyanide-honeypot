import asyncio

from .base import Command


class SuCommand(Command):
    """Switch user ID or become superuser."""

    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        target_user = "root"
        login_shell = False

        if args:
            if args[0] == "-":
                login_shell = True
                if len(args) > 1:
                    target_user = args[1]
            else:
                target_user = args[0]

        if self.emulator.username == target_user:
            return "", "", 0

        self.target_user = target_user
        self.login_shell = login_shell

        self.emulator.pending_input_callback = self._on_password
        self.emulator.pending_input_prompt = "Password: "

        return "Password: ", "", 0

    def _validate_password(self, password: str) -> bool:
        """Check password against config, fallbacks, and honeypot defaults."""
        for user_entry in self.fs.users:
            if user_entry.get("user") == self.target_user:
                if user_entry.get("pass") == password:
                    return True
                break

        if password in ["root", "password", "cyanide", "admin"]:
            return True

        return not password

    def _update_emulator_state(self):
        """Update emulator username and CWD based on target user."""
        self.emulator.username = self.target_user
        if self.target_user == "root":
            if self.login_shell or self.emulator.cwd == "/":
                self.emulator.cwd = "/root"
        elif self.login_shell:
            self.emulator.cwd = f"/home/{self.target_user}"

        if not self.fs.exists(self.emulator.cwd):
            self.fs.mkdir_p(self.emulator.cwd, owner=self.target_user)

    def _on_password(self, password: str) -> tuple[str, str, int]:
        if self._validate_password(password.strip()):
            self._update_emulator_state()
            return "", "", 0
        return "", "su: Authentication failure\n", 1
