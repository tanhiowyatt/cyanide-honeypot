from pathlib import PurePosixPath

from cyanide.vfs.nodes import Directory, File

from .base import Command


class CpCommand(Command):
    async def execute(self, args, input_data=""):
        recursive = "-r" in args or "-R" in args or "--recursive" in args

        clean_args = [a for a in args if not a.startswith("-")]
        if len(clean_args) < 2:
            return "", "cp: missing file operand\n", 1

        dest_str = clean_args[-1]
        sources = clean_args[:-1]

        dest_path = self.emulator.resolve_path(dest_str)
        dest_node = self.fs.get_node(dest_path)

        # If dest doesn't exist, checks later

        dest_is_dir = dest_node and isinstance(dest_node, Directory)

        for src_str in sources:
            src_path = self.emulator.resolve_path(src_str)
            src_node = self.fs.get_node(src_path)

            if not src_node:
                return (
                    "",
                    f"cp: cannot stat '{src_str}': No such file or directory\n",
                    1,
                )

            if isinstance(src_node, Directory):
                if not recursive:
                    return (
                        "",
                        f"cp: -r not specified; omitting directory '{src_str}'\n",
                        1,
                    )

                # Recursive copy
                if dest_is_dir:
                    # Copy INTO dest_dir
                    new_name = src_node.name
                    # Check if exists
                    if dest_node.get_child(new_name):
                        # Merge? Or Overwrite? standard cp -r into existing dir merges/overwrites content
                        # Simplified: remove existing and copy new
                        dest_node.remove_child(new_name)

                    self._copy_node(src_node, dest_node, new_name)
                else:
                    # Copy AS dest_dir (only valid if single source)
                    if len(sources) > 1:
                        return (
                            "",
                            f"cp: target '{dest_str}' is not a directory\n",
                            1,
                        )

                    if dest_node:
                        # Overwrite existing file/dir?
                        # If dest is file, cannot overwrite with dir
                        return (
                            "",
                            f"cp: cannot overwrite non-directory '{dest_str}' with directory '{src_str}'\n",
                            1,
                        )

                    # Create new dir at dest path
                    parent_path = str(PurePosixPath(dest_path).parent)
                    dirname = PurePosixPath(dest_path).name
                    parent = self.fs.get_node(parent_path)

                    if not parent or not isinstance(parent, Directory):
                        return (
                            "",
                            f"cp: cannot create directory '{dest_str}': No such file or directory\n",
                            1,
                        )

                    self._copy_node(src_node, parent, dirname)

            else:
                # File copy
                content = src_node.content

                if dest_is_dir:
                    # Copy into directory
                    new_name = src_node.name
                    if dest_node.get_child(new_name):
                        dest_node.get_child(new_name).content = content
                    else:
                        new_file = File(
                            new_name,
                            parent=dest_node,
                            content=content,
                            owner=self.username,
                            group=self.username,
                        )
                        dest_node.add_child(new_file)
                else:
                    # Copy as dest name
                    if dest_node:
                        dest_node.content = content
                    else:
                        parent_path = str(PurePosixPath(dest_path).parent)
                        filename = PurePosixPath(dest_path).name
                        parent = self.fs.get_node(parent_path)

                        if not parent or not isinstance(parent, Directory):
                            return (
                                "",
                                f"cp: cannot create regular file '{dest_str}': No such file or directory\n",
                                1,
                            )

                        new_file = File(
                            filename,
                            parent=parent,
                            content=content,
                            owner=self.username,
                            group=self.username,
                        )
                        parent.add_child(new_file)

        return "", "", 0

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
