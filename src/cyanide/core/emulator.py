import inspect
import shlex
from dataclasses import dataclass
from typing import Dict, List, Optional, cast

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

    def __init__(
        self,
        fs: FakeFilesystem,
        username: str = "root",
        quarantine_callback=None,
        config=None,
        logger=None,
        session_id=None,
        src_ip=None,
        analytics=None,
    ):
        self.fs = fs
        self.username = username
        self.config = config or {}
        self.quarantine_callback = quarantine_callback
        self.logger = logger
        self.analytics = analytics
        self.session_id = session_id
        self.src_ip = src_ip
        self.dns_cache: dict[str, tuple[str, float]] = {}

        if username == "admin":
            self.cwd = "/home/admin"
        elif username == "root":
            self.cwd = "/root"
        else:
            self.cwd = f"/home/{username}"

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

    def _register_commands(self):
        """Register available commands using the central registry."""
        from cyanide.vfs.commands import COMMAND_MAP

        self.commands: Dict[str, Command] = {}
        for cmd_name, cmd_class in COMMAND_MAP.items():
            self.commands[cmd_name] = cmd_class(self)

        self.commands["dir"] = self.commands.get("ls")

    def resolve_path(self, path: str) -> str:
        """Resolve relative or absolute path to filesystem path."""
        if path.startswith("/"):
            return str(self.fs.resolve(path))
        return str(self.fs.resolve(f"{self.cwd}/{path}"))

    def _should_skip_node(self, node: CommandNode, last_rc: int) -> bool:
        """Determine if the current node should be skipped based on previous result."""
        if node.operator == "||" and last_rc != 0:
            return False
        if node.operator in (";", None):
            return False
        return True

    def _get_next_should_execute(self, node: CommandNode, rc: int) -> bool:
        """Determine if the next node should be executed based on current result."""
        if node.operator == "&&":
            return rc == 0
        if node.operator == "||":
            return rc != 0
        return True

    async def _execute_nodes(self, nodes: List[CommandNode]) -> tuple[str, str, int]:
        full_stdout = ""
        full_stderr = ""
        last_rc = 0
        should_execute = True

        for node in nodes:
            if not should_execute:
                if self._should_skip_node(node, last_rc):
                    should_execute = True
                else:
                    continue

            if node.operator == "&":
                import secrets
                import time

                pid = secrets.SystemRandom().randint(2000, 9000)
                if hasattr(self.fs, "processes"):
                    self.fs.processes.append(
                        {
                            "pid": pid,
                            "tty": "pts/0",
                            "time": "00:00:00",
                            "cmd": node.cmd_line,
                            "user": self.username,
                            "start_time": time.time(),
                        }
                    )
                stdout, stderr, rc = (
                    f"[{secrets.SystemRandom().randint(1, 10)}] {pid}\n",
                    "",
                    0,
                )
            else:
                stdout, stderr, rc = await self._execute_pipeline(node.cmd_line)

            full_stdout += stdout
            full_stderr += stderr
            last_rc = rc

            if len(full_stdout) > self.max_output_size:
                full_stdout = full_stdout[: self.max_output_size] + "\n[output truncated]\n"
                full_stderr += "shell: maximum output size exceeded\n"
                last_rc = 1
                break

            should_execute = self._get_next_should_execute(node, rc)

        return full_stdout, full_stderr, last_rc

    async def execute(self, command_line: str) -> tuple[str, str, int]:
        """Execute a shell command line dealing with chains, pipes, and redirections."""
        if self.pending_input_callback:
            callback = self.pending_input_callback
            self.pending_input_callback = None
            self.pending_input_prompt = None
            res = callback(command_line)
            if inspect.isawaitable(res):
                return await res
            return res

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

        return await self._execute_nodes(nodes)

    def _check_operator(self, command_line: str, i: int) -> Optional[str]:
        """Check for chain operators at the current index."""
        if command_line[i : i + 2] in ("&&", "||"):
            return command_line[i : i + 2]
        if command_line[i] in (";", "&"):
            return command_line[i]
        return None

    def _update_quote_state(self, char: str, in_quote: bool, quote_char: str) -> tuple[bool, str]:
        """Returns new (in_quote, quote_char) boolean states."""
        if not in_quote:
            return True, char
        if char == quote_char:
            return False, ""
        return in_quote, quote_char

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
                in_quote, quote_char = self._update_quote_state(char, in_quote, quote_char)
                current_token += char
                i += 1
                continue

            if not in_quote:
                op = self._check_operator(command_line, i)
                if op:
                    tokens.append((current_token.strip(), op))
                    current_token = ""
                    i += len(op)
                    continue

            current_token += char
            i += 1

        if current_token.strip():
            tokens.append((current_token.strip(), None))

        return [CommandNode(cmd, op) for cmd, op in tokens if cmd]

    def _split_ignore_quotes(self, s: str, delimiter: str) -> list[str]:
        """Split a string by delimiter, but ignore delimiters inside quotes."""
        parts = []
        current = ""
        in_quote = None
        for char in s:
            if char in ("'", '"'):
                if in_quote == char:
                    in_quote = None
                elif in_quote is None:
                    in_quote = char
                current += char
            elif char == delimiter and in_quote is None:
                parts.append(current.strip())
                current = ""
            else:
                current += char
        if current.strip():
            parts.append(current.strip())
        return parts

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

    def _resolve_alias(self, cmd_name: str, params: List[str]) -> tuple[str, List[str]]:
        """Resolve command alias if it exists."""
        if cmd_name in self.aliases:
            alias_val = self.aliases[cmd_name]
            try:
                alias_args = shlex.split(alias_val)
                if alias_args and alias_args[0] != cmd_name:
                    return alias_args[0], alias_args[1:] + params
            except ValueError:
                pass
        return cmd_name, params

    async def _run_command_instance(
        self, cmd_name: str, params: List[str], input_data: str
    ) -> tuple[str, str, int]:
        """Execute the command instance and handle its specific errors/output."""
        if cmd_name not in self.commands:
            return "", f"{cmd_name}: command not found\n", 127

        try:
            from typing import cast

            result = await self.commands[cmd_name].auth_and_execute(params, input_data=input_data)
            return cast(tuple[str, str, int], result)
        except Exception as e:
            return "", f"Command execution error: {e}\n", 1

    async def _execute_single_command(self, cmd_line: str, input_data: str) -> tuple[str, str, int]:
        try:
            args = shlex.split(cmd_line)
        except ValueError:
            return "", "Syntax error\n", 1

        if not args:
            return "", "", 0

        cmd_name, params = self._resolve_alias(args[0], args[1:])

        # Support direct execution of scripts (e.g. ./script.sh)
        if cmd_name not in self.commands:
            abs_path = self.resolve_path(cmd_name)
            if self.fs.exists(abs_path) and not self.fs.is_dir(abs_path):
                # Real bash check: must have +x for direct execution
                if not self.check_permission(abs_path, "x"):
                    return "", f"bash: {cmd_name}: Permission denied\n", 126

                # If it's a file, execute it via bash
                res = await self.commands["bash"].execute([cmd_name] + params, input_data)
                return cast(tuple[str, str, int], res)

        return await self._run_command_instance(cmd_name, params, input_data)

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
            if token == ">>" and i + 1 < len(parts):
                target = parts[i + 1]
                append = True
                i += 2
                continue
            elif token == ">" and i + 1 < len(parts):
                target = parts[i + 1]
                i += 2
                continue

            clean_parts.append(token)
            i += 1

        return shlex.join(clean_parts), target, append

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

        s = re.sub(r"\${([a-zA-Z_]\w*)}", replace_braced, s)

        def replace_simple(match):
            var_name = match.group(1)
            return self.env.get(var_name, "")

        s = re.sub(r"\$([a-zA-Z_]\w*)", replace_simple, s)
        return s
