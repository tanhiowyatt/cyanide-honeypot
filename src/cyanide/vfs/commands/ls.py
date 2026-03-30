import asyncio
import datetime
import posixpath
from typing import Any

from cyanide.vfs.nodes import Directory

from .base import Command


class LsCommand(Command):
    """List directory contents."""

    # Function 246: Executes the 'ls' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the ls command."""
        show_all, long_format, recursive, paths = self._parse_ls_args(args)

        target_path = self.emulator.cwd
        if paths:
            target_path = self.emulator.resolve_path(paths[0])

        target_node = self.fs.get_node(target_path)

        if not target_node:
            err_path = paths[0] if paths else ""
            return "", f"ls: cannot access '{err_path}': No such file or directory\n", 2

        if not recursive:
            nodes_to_list = self._collect_nodes(target_node, show_all)
            return self._format_output(nodes_to_list, long_format)
        else:
            return self._format_recursive(target_path, target_node, show_all, long_format)

    def _parse_ls_args(self, args: list[str]) -> tuple[bool, bool, bool, list[str]]:
        """Parse ls arguments for flags and paths."""
        show_all = False
        long_format = False
        recursive = False
        paths = []
        for arg in args:
            if arg.startswith("-"):
                if "a" in arg:
                    show_all = True
                if "l" in arg:
                    long_format = True
                if "R" in arg:
                    recursive = True
            else:
                paths.append(arg)
        return show_all, long_format, recursive, paths

    def _get_target_node(self, paths: list[str]):
        """Resolve the target path and return the corresponding node."""
        target_path = self.emulator.cwd
        if paths:
            target_path = self.emulator.resolve_path(paths[0])
        return self.fs.get_node(target_path)

    def _collect_nodes(self, target_node, show_all: bool) -> list[tuple]:
        """Collect nodes to be listed based on the target node and show_all flag."""
        if not isinstance(target_node, Directory):
            return [(target_node, target_node.name)]

        children_names = sorted(target_node.children.keys())
        nodes_to_list = []

        if show_all:
            nodes_to_list.append((target_node, "."))
            parent_node = target_node.parent if target_node.parent else target_node
            nodes_to_list.append((parent_node, ".."))

        for name in children_names:
            if not show_all and name.startswith("."):
                continue
            nodes_to_list.append((target_node.children[name], name))

        return nodes_to_list

    def _format_output(self, nodes_to_list: list[tuple], long_format: bool) -> tuple[str, str, int]:
        """Format the collected nodes into the final output string."""
        if long_format:
            return self._format_long(nodes_to_list), "", 0

        if not nodes_to_list:
            return "", "", 0

        stdout = "  ".join([n[1] for n in nodes_to_list if n[1]]) + "\n"
        return stdout, "", 0

    # Function 247: Performs operations related to format long.
    def _format_long(self, nodes_with_names):
        """Format listing in long format (-l)."""
        output = ""
        for node, name in nodes_with_names:
            mtime = node.mtime
            if isinstance(mtime, str):
                try:
                    # Handle common ISO formats or fallback
                    from dateutil import parser  # type: ignore[import-untyped]

                    mtime = parser.parse(mtime)
                except (ImportError, ValueError):
                    mtime = datetime.datetime.now()

            date_str = mtime.strftime("%b %d %H:%M")

            output += f"{node.perm} 1 {node.owner} {node.group} {node.size} {date_str} {name}\n"
        return f"total {len(nodes_with_names) * 4}\n" + output

    def _format_recursive(
        self, path: str, node: Any, show_all: bool, long_format: bool
    ) -> tuple[str, str, int]:
        """Format listing recursively (-R)."""
        if not isinstance(node, Directory):
            return self._format_output([(node, node.name)], long_format)

        output = ""
        queue = [(path, node)]

        while queue:
            curr_path, curr_node = queue.pop(0)
            if not isinstance(curr_node, Directory):
                continue

            nodes = self._collect_nodes(curr_node, show_all)
            if not nodes:
                continue

            if output:
                output += "\n"
            output += f"{curr_path}:\n"

            res_out, _, _ = self._format_output(nodes, long_format)
            output += res_out

            # Sort children to ensure deterministic output for tests
            for name in sorted(curr_node.children.keys()):
                if not show_all and name.startswith("."):
                    continue
                child = curr_node.children[name]
                if isinstance(child, Directory):
                    queue.append((posixpath.join(curr_path, name), child))

        return output, "", 0
