"""
Cyanide Emulated Commands
-------------------------
Registry of all available shell commands and their respective implementations.
"""

from .alias import AliasCommand, UnaliasCommand
from .apt import AptCommand
from .awk import AwkCommand
from .bash import BashCommand
from .cat import CatCommand
from .cd import CdCommand
from .chmod import ChmodCommand
from .cp import CpCommand
from .crontab import CrontabCommand
from .curl import CurlCommand
from .doas import DoasCommand
from .dpkg import DpkgCommand
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
from .rpm import RpmCommand
from .ss import SsCommand
from .su import SuCommand
from .sudo import SudoCommand
from .systemctl import SystemctlCommand
from .tail import TailCommand
from .touch import TouchCommand
from .uname import UnameCommand
from .uptime import UptimeCommand
from .visudo import VisudoCommand
from .w import WCommand
from .wget import WgetCommand
from .who import WhoCommand
from .whoami import WhoamiCommand
from .yum import YumCommand

COMMAND_MAP = {
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
    "touch": TouchCommand,
    "mkdir": MkdirCommand,
    "rmdir": RmdirCommand,
    "rm": RmCommand,
    "cp": CpCommand,
    "mv": MvCommand,
    "find": FindCommand,
    "grep": GrepCommand,
    "head": HeadCommand,
    "tail": TailCommand,
    "awk": AwkCommand,
    "ip": IpCommand,
    "ifconfig": IfconfigCommand,
    "route": RouteCommand,
    "netstat": NetstatCommand,
    "ss": SsCommand,
    "lsof": LsofCommand,
    "env": EnvCommand,
    "history": HistoryCommand,
    "last": LastCommand,
    "finger": FingerCommand,
    "systemctl": SystemctlCommand,
    "journalctl": JournalctlCommand,
    "crontab": CrontabCommand,
    "free": FreeCommand,
    "alias": AliasCommand,
    "unalias": UnaliasCommand,
    "apt": AptCommand,
    "apt-get": AptCommand,
    "dpkg": DpkgCommand,
    "yum": YumCommand,
    "dnf": YumCommand,
    "rpm": RpmCommand,
    "python": PythonCommand,
    "python3": PythonCommand,
    "perl": PerlCommand,
    "gcc": GccCommand,
    "make": MakeCommand,
    "nc": NcCommand,
    "netcat": NcCommand,
    "pkexec": PkexecCommand,
    "doas": DoasCommand,
    "visudo": VisudoCommand,
    "bash": BashCommand,
    "sh": BashCommand,
    "curl": CurlCommand,
    "wget": WgetCommand,
    "ping": PingCommand,
    "uptime": UptimeCommand,
    "vi": EditorCommand,
    "vim": EditorCommand,
    "nano": EditorCommand,
    "ed": EditorCommand,
}

__all__ = ["COMMAND_MAP"] + list(COMMAND_MAP.keys())
