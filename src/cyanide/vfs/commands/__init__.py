"""
Cyanide Emulated Commands
-------------------------
Registry of all available shell commands and their respective implementations.
"""

from .cd import CdCommand
from .ls import LsCommand
from .pwd import PwdCommand
from .cat import CatCommand
from .whoami import WhoamiCommand
from .id import IdCommand
from .echo import EchoCommand
from .uname import UnameCommand
from .ps import PsCommand
from .sudo import SudoCommand
from .help import HelpCommand
from .export import ExportCommand
from .who import WhoCommand
from .w import WCommand
from .file_ops import TouchCommand, MkdirCommand, RmdirCommand, RmCommand, CpCommand, MvCommand
from .text_ops import GrepCommand, HeadCommand, TailCommand
from .misc import PingCommand, EditorCommand
from .curl import CurlCommand

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
    
    # Misc/Realism
    "curl": CurlCommand,
    "ping": PingCommand,
    "vi": EditorCommand,
    "vim": EditorCommand,
    "nano": EditorCommand,
    "ed": EditorCommand
}

__all__ = ["COMMAND_MAP"] + list(COMMAND_MAP.keys())
