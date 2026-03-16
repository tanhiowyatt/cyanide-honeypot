from cyanide.vfs.nodes import Directory, File

from .base import Command


class CpCommand(Command):
    # Function 219: Executes the 'cp' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        recursive = "-r" in args or "-R" in args or "--recursive" in args

        clean_args = [a for a in args if not a.startswith("-")]
        if len(clean_args) < 2:
            return "", "cp: missing file operand\n", 1

        dest_str = clean_args[-1]
        sources = clean_args[:-1]

        dest_path = self.emulator.resolve_path(dest_str)

        for src_str in sources:
            src_path = self.emulator.resolve_path(src_str)

            if not self.fs.exists(src_path):
                return (
                    "",
                    f"cp: cannot stat '{src_str}': No such file or directory\n",
                    1,
                )

            if not self.fs.copy(src_path, dest_path, recursive=recursive):
                if self.fs.is_dir(src_path) and not recursive:
                    return (
                        "",
                        f"cp: -r not specified; omitting directory '{src_str}'\n",
                        1,
                    )
                return (
                    "",
                    f"cp: cannot copy '{src_str}' to '{dest_str}'\n",
                    1,
                )

        return "", "", 0

    # Function 220: Performs operations related to copy node.
    def _copy_node(self, src_node, parent_node, new_name):
        """Recursively copy a node (File or Directory) to a new parent with a new name."""
        if isinstance(src_node, File):
            new_file = File(
                new_name,
                parent=parent_node,
                content=src_node.content,
                owner=self.username,
                group=self.username,
            )
            parent_node.add_child(new_file)
        elif isinstance(src_node, Directory):
            new_dir = Directory(
                new_name,
                parent=parent_node,
                owner=self.username,
                group=self.username,
            )
            parent_node.add_child(new_dir)
            for child in src_node.children.values():
                self._copy_node(child, new_dir, child.name)
