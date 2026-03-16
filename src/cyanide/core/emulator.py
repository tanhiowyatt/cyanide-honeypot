import shlex
from dataclasses import dataclass
from typing import Dict, List, Optional

from cyanide.vfs.commands.base import Command
from cyanide.vfs.engine import FakeFilesystem


@dataclass
class CommandNode:
    cmd_line: str
    operator: Optional[str] = None


class ShellEmulator:
    """Fake Linux shell emulator for honeypot command execution.

    Provides realistic command execution behavior including:
    - Filesystem navigation and manipulation
    - Pipes (|)
    - Redirections (>, >>)
    - Command chaining (;, &&, ||)
    """

    # Function 18: Initializes the class instance and its attributes.
    def __init__(
        self, fs: FakeFilesystem, username: str = "root", quarantine_callback=None, config=None
    ):
        self.fs = fs
        self.username = username
        self.config = config or {}
        self.quarantine_callback = quarantine_callback
        self.dns_cache: dict[str, tuple[str, float]] = {}
        self.cwd = (
            "/home/admin"
            if username == "admin"
            else "/root" if username == "root" else f"/home/{username}"
        )
        if not self.fs.exists(self.cwd):
            self.cwd = "/"

        self.max_chain_depth = self.config.get("shell", {}).get("max_chain_depth", 100)
        self.max_output_size = self.config.get("shell", {}).get("max_output_size", 1024 * 1024)

        self.pending_input_callback = None
        self.pending_input_prompt = None
        self.history: list[str] = []
        self.env: dict[str, str] = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": self.cwd,
            "USER": self.username,
            "SHELL": "/bin/bash",
            "TERM": "xterm-256color",
        }
        self.aliases: dict[str, str] = {
            "l": "ls -CF",
            "la": "ls -A",
            "ll": "ls -alF",
            "ls": "ls --color=auto",
        }

        self._register_commands()

    # Function 19: Performs operations related to check permission.
    def check_permission(self, path: str, mode: str = "r") -> bool:
        """Check if current user has permission for path."""
        if self.username == "root":
            return True

        abs_path = self.resolve_path(path)
        if abs_path == "/root" or abs_path.startswith("/root/"):
            return False

        node = self.fs.get_node(path)
        if not node:
            return False

        perms = node.perm
        owner_perm = perms[1:4]
        group_perm = perms[4:7]
        other_perm = perms[7:10]

        needed = ""
        if "r" in mode:
            needed += "r"
        if "w" in mode:
            needed += "w"
        if "x" in mode:
            needed += "x"

        scope_perm = other_perm
        if self.username == node.owner:
            scope_perm = owner_perm
        elif self.username == node.group:
            scope_perm = group_perm

        for char in needed:
            if char not in scope_perm:
                return False

        return True

    # Function 20: Performs operations related to register commands.
    def _register_commands(self):
        """Register available commands using the central registry."""
        from cyanide.vfs.commands import COMMAND_MAP

        self.commands: Dict[str, Command] = {}
        for cmd_name, cmd_class in COMMAND_MAP.items():
            self.commands[cmd_name] = cmd_class(self)

        self.commands["dir"] = self.commands.get("ls")

    # Function 21: Performs operations related to resolve path.
    def resolve_path(self, path: str) -> str:
        """Resolve relative or absolute path to filesystem path."""
        if path.startswith("/"):
            return str(self.fs.resolve(path))
        return str(self.fs.resolve(f"{self.cwd}/{path}"))

    # Function 22: Executes the 'emulator' command logic within the virtual filesystem.
    async def execute(self, command_line: str) -> tuple[str, str, int]:
        """Execute a shell command line dealing with chains, pipes, and redirections.

        Args:
            command_line: Complete command line string.

        Returns:
            tuple: (stdout, stderr, return_code) - Aggregated from the executed chain.
        """
        if self.pending_input_callback:
            callback = self.pending_input_callback
            self.pending_input_callback = None
            self.pending_input_prompt = None
            return await callback(command_line)

        if not command_line.strip():
            return "", "", 0

        self.history.append(command_line.strip())

        command_line = self._expand_vars(command_line)

        try:
            nodes = self._parse_chain(command_line)
        except Exception as e:
            return "", f"Parse error: {str(e)}\n", 2

        if len(nodes) > self.max_chain_depth:
            return "", "shell: maximum command chain depth exceeded\n", 1

        full_stdout = ""
        full_stderr = ""
        last_rc = 0

        should_execute = True

        for i, node in enumerate(nodes):
            if not should_execute:
                if node.operator == "||" and last_rc != 0:
                    should_execute = True
                elif node.operator == ";" or node.operator is None:
                    should_execute = True
                else:
                    pass
                continue

            stdout, stderr, rc = await self._execute_pipeline(node.cmd_line)

            full_stdout += stdout
            full_stderr += stderr
            last_rc = rc

            if len(full_stdout) > self.max_output_size:
                full_stdout = full_stdout[: self.max_output_size] + "\n[output truncated]\n"
                full_stderr += "shell: maximum output size exceeded\n"
                last_rc = 1
                break

            if node.operator == "&&":
                should_execute = rc == 0
            elif node.operator == "||":
                should_execute = rc != 0
            elif node.operator == ";":
                should_execute = True

        return full_stdout, full_stderr, last_rc

    # Function 23: Performs operations related to parse chain.
    def _parse_chain(self, command_line: str) -> List[CommandNode]:
        """Split command line by operators &&, ||, ; dealing with quotes."""

        tokens: List[tuple[str, Optional[str]]] = []
        current_token = ""
        in_quote = False
        quote_char = ""

        i = 0
        while i < len(command_line):
            char = command_line[i]

            if char in ("'", '"'):
                if not in_quote:
                    in_quote = True
                    quote_char = char
                elif char == quote_char:
                    in_quote = False
                current_token += char

            elif not in_quote:
                if command_line[i : i + 2] == "&&":
                    tokens.append((current_token.strip(), "&&"))
                    current_token = ""
                    i += 1
                elif command_line[i : i + 2] == "||":
                    tokens.append((current_token.strip(), "||"))
                    current_token = ""
                    i += 1
                elif char == ";":
                    tokens.append((current_token.strip(), ";"))
                    current_token = ""
                else:
                    current_token += char
            else:
                current_token += char

            i += 1

        if current_token.strip():
            tokens.append((current_token.strip(), None))

        return [CommandNode(cmd, op) for cmd, op in tokens if cmd]

    # Function 24: Performs operations related to execute pipeline.
    async def _execute_pipeline(self, pipeline_str: str) -> tuple[str, str, int]:
        """Execute a single pipeline (A | B | C)."""
        segments = self._split_ignore_quotes(pipeline_str, "|")

        input_data = ""
        last_rc = 0
        err_out = ""

        for i, segment in enumerate(segments):
            cmd_str, redirect_target, append_mode = self._parse_redirections(segment)

            stdout, stderr, rc = await self._execute_single_command(cmd_str, input_data)

            last_rc = rc
            if stderr:
                err_out += stderr

            if redirect_target:
                if append_mode:
                    existing = ""
                    abs_target = self.resolve_path(redirect_target)
                    if self.fs.exists(abs_target):
                        existing = self.fs.get_content(abs_target)
                    self._write_file(redirect_target, existing + stdout)
                else:
                    self._write_file(redirect_target, stdout)

                input_data = ""
            else:
                input_data = stdout

        return input_data, err_out, last_rc

    # Function 25: Performs operations related to execute single command.
    async def _execute_single_command(self, cmd_line: str, input_data: str) -> tuple[str, str, int]:
        try:
            args = shlex.split(cmd_line)
        except ValueError:
            return "", "Syntax error\n", 1

        if not args:
            return "", "", 0

        cmd_name = args[0]
        params = args[1:]

        if cmd_name in self.aliases:
            alias_val = self.aliases[cmd_name]
            try:
                alias_args = shlex.split(alias_val)
                if alias_args and alias_args[0] != cmd_name:
                    cmd_name = alias_args[0]
                    params = alias_args[1:] + params
            except ValueError:
                pass

        if cmd_name in self.commands:
            try:
                from typing import cast

                result = await self.commands[cmd_name].auth_and_execute(
                    params, input_data=input_data
                )
                return cast(tuple[str, str, int], result)
            except Exception as e:
                return "", f"Command execution error: {e}\n", 1
        else:
            return "", f"{cmd_name}: command not found\n", 127

    # Function 26: Performs operations related to parse redirections.
    def _parse_redirections(self, cmd: str) -> tuple[str, Optional[str], bool]:
        """Extract redirection > or >> from command string.
        Returns (clean_cmd, target_file, is_append)
        """

        parts = shlex.split(cmd)
        target = None
        append = False
        clean_parts = []

        i = 0
        while i < len(parts):
            token = parts[i]
            if token == ">>":
                if i + 1 < len(parts):
                    target = parts[i + 1]
                    append = True
                    i += 2
                    continue
            elif token == ">":
                if i + 1 < len(parts):
                    target = parts[i + 1]
                    i += 2
                    continue

            clean_parts.append(token)
            i += 1

        return shlex.join(clean_parts), target, append

    # Function 27: Performs operations related to split ignore quotes.
    def _split_ignore_quotes(self, s: str, separator: str) -> List[str]:
        tokens = []
        current = ""
        in_quote = False
        quote_char = ""
        for char in s:
            if char in ("'", '"'):
                if not in_quote:
                    in_quote = True
                    quote_char = char
                elif char == quote_char:
                    in_quote = False

            if char == separator and not in_quote:
                tokens.append(current.strip())
                current = ""
            else:
                current += char
        tokens.append(current.strip())
        return tokens

    # Function 28: Performs operations related to write file.
    def _write_file(self, path: str, content: str):
        """Helper to write to fake fs."""
        abs_path = self.resolve_path(path)
        self.fs.mkfile(abs_path, content=content, owner=self.username, group=self.username)

    def _expand_vars(self, s: str) -> str:
        """Expand environment variables $VAR or ${VAR} in string."""
        import re

        def replace_braced(match):
            var_name = match.group(1)
            return self.env.get(var_name, "")

        s = re.sub(r"\${([a-zA-Z_][a-zA-Z0-9_]*)}", replace_braced, s)

        def replace_simple(match):
            var_name = match.group(1)
            return self.env.get(var_name, "")

        s = re.sub(r"\$([a-zA-Z_][a-zA-Z0-9_]*)", replace_simple, s)
        return s
