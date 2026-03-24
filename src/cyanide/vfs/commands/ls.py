import asyncio

from cyanide.vfs.nodes import Directory

from .base import Command


class LsCommand(Command):
    """List directory contents."""

    # Function 246: Executes the 'ls' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        """Execute the ls command."""
        show_all, long_format, paths = self._parse_ls_args(args)
        target_node = self._get_target_node(paths)

        if not target_node:
            err_path = paths[0] if paths else ""
            return "", f"ls: cannot access '{err_path}': No such file or directory\n", 2

        nodes_to_list = self._collect_nodes(target_node, show_all)
        return self._format_output(nodes_to_list, long_format)

    def _parse_ls_args(self, args: list[str]) -> tuple[bool, bool, list[str]]:
        """Parse ls arguments for flags and paths."""
        show_all = False
        long_format = False
        paths = []
        for arg in args:
            if arg.startswith("-"):
                if "a" in arg:
                    show_all = True
                if "l" in arg:
                    long_format = True
            else:
                paths.append(arg)
        return show_all, long_format, paths

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
                    import datetime

                    mtime = datetime.datetime.now()

            date_str = mtime.strftime("%b %d %H:%M")

            output += f"{node.perm} 1 {node.owner} {node.group} {node.size} {date_str} {name}\n"
        return f"total {len(nodes_with_names) * 4}\n" + output
