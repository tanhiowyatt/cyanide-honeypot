from .base import Command


class SuCommand(Command):
    """Switch user ID or become superuser."""

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

        # If already that user, just return
        if self.emulator.username == target_user:
            return "", "", 0

        # For honeypot realism, we always "prompt" for password when becoming root
        # or switching from non-root to any user.
        self.target_user = target_user
        self.login_shell = login_shell
        
        self.emulator.pending_input_callback = self._on_password
        self.emulator.pending_input_prompt = "Password: "
        
        return "Password: ", "", 0

    async def _on_password(self, password: str) -> tuple[str, str, int]:
        # Realistic behavior: any non-empty password works, or strictly 'root'
        # Let's go with 'root' as the magic word, or anything if you want it to be easy.
        # But actually, standard honeypots often accept anything to let them in.
        # User said "make request for root password", let's assume 'root' or 'cyanide'.
        # For simplicity and maximum "capture", let's accept 'root' or 'password'.
        
        valid_passwords = ["root", "password", "cyanide", "admin"]
        
        if password.strip() in valid_passwords or not password.strip():
            # Success
            self.emulator.username = self.target_user
            if self.target_user == "root":
                if self.login_shell or self.emulator.cwd == "/":
                    self.emulator.cwd = "/root"
            else:
                if self.login_shell:
                    self.emulator.cwd = f"/home/{self.target_user}"
            
            # Ensure dir exists
            if not self.fs.exists(self.emulator.cwd):
                self.fs.mkdir_p(self.emulator.cwd, owner=self.target_user)
                
            return "", "", 0
        else:
            return "", "su: Authentication failure\n", 1
