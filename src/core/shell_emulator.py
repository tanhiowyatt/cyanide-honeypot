import shlex
import time
from .fake_filesystem import FakeFilesystem
from ..commands.cd import CdCommand
from ..commands.ls import LsCommand
from ..commands.pwd import PwdCommand
from ..commands.cat import CatCommand
from ..commands.whoami import WhoamiCommand
from ..commands.id import IdCommand
from ..commands.echo import EchoCommand
from ..commands.uname import UnameCommand
from ..commands.ps import PsCommand
from ..commands.sudo import SudoCommand
from ..commands.help import HelpCommand
from ..commands.export import ExportCommand
from ..commands.who import WhoCommand
from ..commands.w import WCommand

class ShellEmulator:
    """Fake Linux shell emulator for honeypot command execution.
    
    Provides realistic command execution behavior including filesystem navigation,
    file reading, process listing, and other common Linux commands. All operations
    are performed against a fake filesystem.
    """
    
    def __init__(self, fs: FakeFilesystem, username: str = "root"):
        """Initialize shell emulator with filesystem and user context.
        
        Args:
            fs: FakeFilesystem instance for file operations.
            username: Username for the session (affects paths and permissions).
        """
        self.fs = fs
        self.username = username
        self.cwd = "/home/admin" if username == "admin" else "/root" if username == "root" else f"/home/{username}"
        if not self.fs.exists(self.cwd):
            self.cwd = "/"
            
        self._register_commands()

    def _register_commands(self):
        """Register available commands."""
        self.commands = {
            "cd": CdCommand(self),
            "ls": LsCommand(self),
            "dir": LsCommand(self),
            "pwd": PwdCommand(self),
            "cat": CatCommand(self),
            "whoami": WhoamiCommand(self),
            "id": IdCommand(self),
            "echo": EchoCommand(self),
            "uname": UnameCommand(self),
            "ps": PsCommand(self),
            "sudo": SudoCommand(self),
            "help": HelpCommand(self),
            "export": ExportCommand(self),
            "who": WhoCommand(self),
            "w": WCommand(self),
        }

    def resolve_path(self, path: str) -> str:
        """Resolve relative or absolute path to filesystem path.
        
        Args:
            path: Path to resolve (absolute or relative to cwd).
            
        Returns:
            str: Resolved absolute path in filesystem.
        """
        if path.startswith("/"):
            return self.fs.resolve(path)
        return self.fs.resolve(f"{self.cwd}/{path}")

    def execute(self, command_line: str) -> tuple[str, str, int]:
        """Execute a shell command and return output.
        
        Args:
            command_line: Complete command line string to parse and execute.
            
        Returns:
            tuple: (stdout, stderr, return_code) where:
                - stdout: Standard output from command
                - stderr: Standard error from command  
                - return_code: Exit code (0 for success, >0 for error)
                
        Note:
            Supports common Linux commands: cd, ls, pwd, cat, whoami, id,
            echo, uname, ps, sudo, export, who, w.
        """
        if not command_line.strip():
            return "", "", 0

        try:
            args = shlex.split(command_line)
        except ValueError:
            return "", "Syntax error\n", 1

        cmd_name = args[0]
        params = args[1:]
        
        if cmd_name in self.commands:
            return self.commands[cmd_name].execute(params)
        else:
            return "", f"{cmd_name}: command not found\n", 127
