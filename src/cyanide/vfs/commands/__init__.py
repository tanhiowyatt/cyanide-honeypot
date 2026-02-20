"""
Cyanide Emulated Commands
-------------------------
Registry of all available shell commands and their respective implementations.
"""

from .awk import AwkCommand
from .cat import CatCommand
from .cd import CdCommand
from .curl import CurlCommand
from .echo import EchoCommand
from .export import ExportCommand
from .file_ops import (
    CpCommand,
    MkdirCommand,
    MvCommand,
    RmCommand,
    RmdirCommand,
    TouchCommand,
)
from .help import HelpCommand
from .id import IdCommand
from .ls import LsCommand
from .misc import EditorCommand, PingCommand
from .ps import PsCommand
from .pwd import PwdCommand
from .su import SuCommand
from .sudo import SudoCommand
from .text_ops import GrepCommand, HeadCommand, TailCommand
from .uname import UnameCommand
from .w import WCommand
from .wget import WgetCommand
from .who import WhoCommand
from .whoami import WhoamiCommand

# Central command registry
COMMAND_MAP = {
    # Navigation/Basics
    "cd": CdCommand,
    "ls": LsCommand,
    "pwd": PwdCommand,
    "whoami": WhoamiCommand,
    "id": IdCommand,
    "echo": EchoCommand,
    "uname": UnameCommand,
    "ps": PsCommand,
    "sudo": SudoCommand,
    "su": SuCommand,
    "help": HelpCommand,
    "export": ExportCommand,
    "who": WhoCommand,
    "w": WCommand,
    "cat": CatCommand,
    # File Operations
    "touch": TouchCommand,
    "mkdir": MkdirCommand,
    "rmdir": RmdirCommand,
    "rm": RmCommand,
    "cp": CpCommand,
    "mv": MvCommand,
    # Text Processing
    "grep": GrepCommand,
    "head": HeadCommand,
    "tail": TailCommand,
    "awk": AwkCommand,
    # Misc/Realism
    "curl": CurlCommand,
    "wget": WgetCommand,
    "ping": PingCommand,
    "vi": EditorCommand,
    "vim": EditorCommand,
    "nano": EditorCommand,
    "ed": EditorCommand,
}

__all__ = ["COMMAND_MAP"] + list(COMMAND_MAP.keys())
