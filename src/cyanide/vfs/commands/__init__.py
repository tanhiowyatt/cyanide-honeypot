"""
Cyanide Emulated Commands
-------------------------
Registry of all available shell commands and their respective implementations.
"""

from .alias import AliasCommand
from .awk import AwkCommand
from .bash import BashCommand
from .cat import CatCommand
from .cd import CdCommand
from .chmod import ChmodCommand
from .cp import CpCommand
from .crontab import CrontabCommand
from .curl import CurlCommand
from .doas import DoasCommand
from .echo import EchoCommand
from .editor import EditorCommand
from .env import EnvCommand
from .export import ExportCommand
from .find import FindCommand
from .finger import FingerCommand
from .free import FreeCommand
from .gcc import GccCommand
from .grep import GrepCommand
from .head import HeadCommand
from .help import HelpCommand
from .history import HistoryCommand
from .id import IdCommand
from .ifconfig import IfconfigCommand
from .ip import IpCommand
from .journalctl import JournalctlCommand
from .last import LastCommand
from .ls import LsCommand
from .lsof import LsofCommand
from .make import MakeCommand
from .mkdir import MkdirCommand
from .mv import MvCommand
from .nc import NcCommand
from .netstat import NetstatCommand
from .perl import PerlCommand
from .ping import PingCommand
from .pkexec import PkexecCommand
from .ps import PsCommand
from .pwd import PwdCommand
from .python import PythonCommand
from .rm import RmCommand
from .rmdir import RmdirCommand
from .route import RouteCommand
from .ss import SsCommand
from .su import SuCommand
from .sudo import SudoCommand
from .systemctl import SystemctlCommand
from .tail import TailCommand
from .touch import TouchCommand
from .uname import UnameCommand
from .visudo import VisudoCommand
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
    "chmod": ChmodCommand,
    # File Operations
    "touch": TouchCommand,
    "mkdir": MkdirCommand,
    "rmdir": RmdirCommand,
    "rm": RmCommand,
    "cp": CpCommand,
    "mv": MvCommand,
    "find": FindCommand,
    # Text Processing
    "grep": GrepCommand,
    "head": HeadCommand,
    "tail": TailCommand,
    "awk": AwkCommand,
    # Networking
    "ip": IpCommand,
    "ifconfig": IfconfigCommand,
    "route": RouteCommand,
    "netstat": NetstatCommand,
    "ss": SsCommand,
    "lsof": LsofCommand,
    # System
    "env": EnvCommand,
    "history": HistoryCommand,
    "last": LastCommand,
    "finger": FingerCommand,
    "systemctl": SystemctlCommand,
    "journalctl": JournalctlCommand,
    "crontab": CrontabCommand,
    "free": FreeCommand,
    "alias": AliasCommand,
    # Dev Tools
    "python": PythonCommand,
    "python3": PythonCommand,
    "perl": PerlCommand,
    "gcc": GccCommand,
    "make": MakeCommand,
    "nc": NcCommand,
    "netcat": NcCommand,
    # Privilege Escalation
    "pkexec": PkexecCommand,
    "doas": DoasCommand,
    "visudo": VisudoCommand,
    "bash": BashCommand,
    "sh": BashCommand,
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
