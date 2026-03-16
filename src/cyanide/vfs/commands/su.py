from .base import Command


class SuCommand(Command):
    """Switch user ID or become superuser."""

    # Function 266: Executes the 'su' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
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

    # Function 267: Performs operations related to on password.
    async def _on_password(self, password: str) -> tuple[str, str, int]:

        valid_passwords = ["root", "password", "cyanide", "admin"]

        if password.strip() in valid_passwords or not password.strip():
            self.emulator.username = self.target_user
            if self.target_user == "root":
                if self.login_shell or self.emulator.cwd == "/":
                    self.emulator.cwd = "/root"
            else:
                if self.login_shell:
                    self.emulator.cwd = f"/home/{self.target_user}"

            if not self.fs.exists(self.emulator.cwd):
                self.fs.mkdir_p(self.emulator.cwd, owner=self.target_user)

            return "", "", 0
        else:
            return "", "su: Authentication failure\n", 1
