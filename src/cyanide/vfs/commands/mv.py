from pathlib import PurePosixPath

from cyanide.vfs.nodes import Directory

from .base import Command


class MvCommand(Command):
    async def execute(self, args, input_data=""):
        if len(args) < 2:
            return "", "mv: missing file operand\n", 1

        clean_args = [a for a in args if not a.startswith("-")]
        if len(clean_args) < 2:
            return "", "mv: missing destination file operand\n", 1

        dest_str = clean_args[-1]
        sources = clean_args[:-1]

        dest_path = self.emulator.resolve_path(dest_str)
        dest_node = self.fs.get_node(dest_path)
        dest_is_dir = isinstance(dest_node, Directory)

        for src_str in sources:
            src_path = self.emulator.resolve_path(src_str)
            src_node = self.fs.get_node(src_path)

            if not src_node:
                return (
                    "",
                    f"mv: cannot stat '{src_str}': No such file or directory\n",
                    1,
                )

            # Unlink from old parent
            src_node.parent.remove_child(src_node.name)

            if dest_is_dir:
                # Move into
                target_name = src_node.name
                if dest_node.get_child(target_name):
                    # Overwrite? usually yes.
                    dest_node.remove_child(target_name)

                src_node.parent = dest_node
                src_node.name = target_name
                dest_node.add_child(src_node)
            else:
                # Rename/Move to new path
                parent_path = str(PurePosixPath(dest_path).parent)
                target_name = PurePosixPath(dest_path).name
                parent = self.fs.get_node(parent_path)

                if not parent or not isinstance(parent, Directory):
                    return (
                        "",
                        f"mv: cannot move '{src_str}' to '{dest_str}': No such file or directory\n",
                        1,
                    )

                if parent.get_child(target_name):
                    # Overwrite existing dest file
                    parent.remove_child(target_name)

                src_node.parent = parent
                src_node.name = target_name
                parent.add_child(src_node)

        return "", "", 0
