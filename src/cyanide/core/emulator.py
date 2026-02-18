import shlex
from dataclasses import dataclass
from typing import List, Optional

from cyanide.vfs.provider import FakeFilesystem


@dataclass
class CommandNode:
    cmd_line: str
    operator: Optional[str] = None  # separator after this command: ';', '&&', '||', or None


class ShellEmulator:
    """Fake Linux shell emulator for honeypot command execution.

    Provides realistic command execution behavior including:
    - Filesystem navigation and manipulation
    - Pipes (|)
    - Redirections (>, >>)
    - Command chaining (;, &&, ||)
    """

    def __init__(
        self, fs: FakeFilesystem, username: str = "root", quarantine_callback=None, config=None
    ):
        self.fs = fs
        self.username = username
        self.config = config or {}
        # Callback(filename, content) -> void
        self.quarantine_callback = quarantine_callback
        self.dns_cache = {}  # Cache: {hostname: (ip, expiry_timestamp)}
        self.cwd = (
            "/home/admin"
            if username == "admin"
            else "/root" if username == "root" else f"/home/{username}"
        )
        if not self.fs.exists(self.cwd):
            self.cwd = "/"

        self._register_commands()

    def check_permission(self, path: str, mode: str = "r") -> bool:
        """Check if current user has permission for path."""
        # Root can do anything
        if self.username == "root":
            return True

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

        # Determine applicable scope
        scope_perm = other_perm
        if self.username == node.owner:
            scope_perm = owner_perm
        elif self.username == node.group:
            scope_perm = group_perm

        # Check
        for char in needed:
            if char not in scope_perm:
                return False

        return True

    def _register_commands(self):
        """Register available commands using the central registry."""
        from cyanide.vfs.commands import COMMAND_MAP

        self.commands = {}
        for cmd_name, cmd_class in COMMAND_MAP.items():
            self.commands[cmd_name] = cmd_class(self)

        # Add manual aliases
        self.commands["dir"] = self.commands.get("ls")

    def resolve_path(self, path: str) -> str:
        """Resolve relative or absolute path to filesystem path."""
        if path.startswith("/"):
            return self.fs.resolve(path)
        return self.fs.resolve(f"{self.cwd}/{path}")

    async def execute(self, command_line: str) -> tuple[str, str, int]:
        """Execute a shell command line dealing with chains, pipes, and redirections.

        Args:
            command_line: Complete command line string.

        Returns:
            tuple: (stdout, stderr, return_code) - Aggregated from the executed chain.
        """
        if not command_line.strip():
            return "", "", 0

        # 1. Parse into a chain of commands separated by operators
        try:
            nodes = self._parse_chain(command_line)
        except Exception as e:
            return "", f"Parse error: {str(e)}\n", 2

        full_stdout = ""
        full_stderr = ""
        last_rc = 0

        should_execute = True

        for i, node in enumerate(nodes):
            if not should_execute:
                # Still need to process operator to see if *next* one should execute logic
                # For example A && B || C. If A fails, B skipped. Operator of B is ||.
                # Since B skipped, we check if we should reset for C?
                # Simplified logic:
                if node.operator == "||" and last_rc != 0:
                    should_execute = True
                elif node.operator == ";" or node.operator is None:
                    should_execute = True
                else:
                    # && with last_rc != 0 -> continue skipping
                    pass
                continue

            # Execute the pipeline (which might be a single command)
            stdout, stderr, rc = await self._execute_pipeline(node.cmd_line)

            full_stdout += stdout
            full_stderr += stderr
            last_rc = rc

            # Decide validation for next node
            if node.operator == "&&":
                should_execute = rc == 0
            elif node.operator == "||":
                should_execute = rc != 0
            elif node.operator == ";":
                should_execute = True

        return full_stdout, full_stderr, last_rc

    def _parse_chain(self, command_line: str) -> List[CommandNode]:
        """Split command line by operators &&, ||, ; dealing with quotes."""
        # This is a basic parser. A full lexer would be better but overkill.
        # We'll use a regex that splits but captures delimiters, then reconstruct.
        # NOTE: This simple regex might fail inside quotes.
        # Ideally we tokenize properly. For a honeypot, a slightly smarter split is usually enough.

        # Placeholder for proper tokenization.
        # We hide quoted strings first to avoid splitting inside them.

        tokens = []
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
                # Check for operators
                if command_line[i : i + 2] == "&&":
                    tokens.append((current_token.strip(), "&&"))
                    current_token = ""
                    i += 1  # skip extra char
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

    async def _execute_pipeline(self, pipeline_str: str) -> tuple[str, str, int]:
        """Execute a single pipeline (A | B | C)."""
        # Split by pipe '|' respecting quotes
        segments = self._split_ignore_quotes(pipeline_str, "|")

        input_data = ""
        last_rc = 0
        err_out = ""

        for i, segment in enumerate(segments):
            # Parse redirections > and >>
            cmd_str, redirect_target, append_mode = self._parse_redirections(segment)

            stdout, stderr, rc = await self._execute_single_command(cmd_str, input_data)

            last_rc = rc
            if stderr:
                err_out += stderr

            if redirect_target:
                # Redirect output
                # mode = 'a' if append_mode else 'w'
                # For fake fs, we need read/write logic
                if append_mode:
                    # simplistic append
                    existing = ""
                    abs_target = self.resolve_path(redirect_target)
                    if self.fs.exists(abs_target):
                        existing = self.fs.get_content(abs_target)
                    self._write_file(redirect_target, existing + stdout)
                else:
                    self._write_file(redirect_target, stdout)

                input_data = ""  # Consumed by file
            else:
                input_data = stdout  # Pass to next pipe

        return input_data, err_out, last_rc

    async def _execute_single_command(self, cmd_line: str, input_data: str) -> tuple[str, str, int]:
        try:
            args = shlex.split(cmd_line)
        except ValueError:
            return "", "Syntax error\n", 1

        if not args:
            return "", "", 0

        cmd_name = args[0]
        params = args[1:]

        if cmd_name in self.commands:
            # All commands must be async now
            try:
                return await self.commands[cmd_name].execute(params, input_data=input_data)
            except Exception as e:
                # Fallback or error report
                return "", f"Command execution error: {e}\n", 1
        else:
            return "", f"{cmd_name}: command not found\n", 127

    def _parse_redirections(self, cmd: str) -> tuple[str, Optional[str], bool]:
        """Extract redirection > or >> from command string.
        Returns (clean_cmd, target_file, is_append)
        """
        # Very simple naive parser, assumes redirection is at the end or separated by spaces
        # TODO: Handle quotes properly

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

        # Reconstruct command line for the command execution
        return shlex.join(clean_parts), target, append

    def _split_ignore_quotes(self, s: str, separator: str) -> List[str]:
        # Helper to split by separator but ignore if in quotes
        # Similar logic to _parse_chain but simpler
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

    def _write_file(self, path: str, content: str):
        """Helper to write to fake fs."""
        abs_path = self.resolve_path(path)
        self.fs.mkfile(abs_path, content=content, owner=self.username, group=self.username)
