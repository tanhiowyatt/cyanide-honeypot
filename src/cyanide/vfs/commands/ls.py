from cyanide.vfs.nodes import Directory

from .base import Command


class LsCommand(Command):
    """List directory contents."""

    # Function 246: Executes the 'ls' command logic within the virtual filesystem.
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the ls command.

        Args:
            args: Command arguments (flags like -l, -a and paths).

        Returns:
            tuple: (stdout, stderr, return_code)
        """
        show_all = False
        long_format = False
        target_path = self.emulator.cwd

        paths = []
        for arg in args:
            if arg.startswith("-"):
                if "a" in arg:
                    show_all = True
                if "l" in arg:
                    long_format = True
            else:
                paths.append(arg)

        if paths:
            target_path = self.emulator.resolve_path(paths[0])

        target_node = self.fs.get_node(target_path)

        if not target_node:
            return (
                "",
                f"ls: cannot access '{paths[0] if paths else ''}': No such file or directory\n",
                2,
            )

        if not isinstance(target_node, Directory):
            if long_format:
                return self._format_long([(target_node, target_node.name)]), "", 0
            return f"{target_node.name}\n", "", 0

        children_names = sorted(target_node.children.keys())
        nodes_to_list = []

        if show_all:
            nodes_to_list.append((target_node, "."))
            if target_node.parent:
                nodes_to_list.append((target_node.parent, ".."))
            else:
                nodes_to_list.append((target_node, ".."))

        for name in children_names:
            if not show_all and name.startswith("."):
                continue
            nodes_to_list.append((target_node.children[name], name))

        if long_format:
            return self._format_long(nodes_to_list), "", 0

        if not nodes_to_list:
            return "", "", 0

        return "  ".join([n[1] for n in nodes_to_list if n[1]]) + "\n", "", 0

    # Function 247: Performs operations related to format long.
    def _format_long(self, nodes_with_names):
        """Format listing in long format (-l)."""
        output = ""
        for node, name in nodes_with_names:
            date_str = node.mtime.strftime("%b %d %H:%M")

            output += f"{node.perm} 1 {node.owner} {node.group} {node.size} {date_str} {name}\n"
        return f"total {len(nodes_with_names) * 4}\n" + output
