import argparse
import time
from pathlib import PurePosixPath
from .base import Command
from core.filesystem_nodes import File, Directory

class FileOpCommand(Command):
    """Base for file operations."""
    pass

class TouchCommand(FileOpCommand):
    async def execute(self, args, input_data=""):
        if not args:
            return "", "touch: missing file operand\n", 1
            
        for arg in args:
            # Ignore flags for now
            if arg.startswith("-"): continue
            
            path = self.emulator.resolve_path(arg)
            if self.fs.exists(path):
                # Update timestamp (fake)
                pass
            else:
                # Create empty file
                parent_path = str(PurePosixPath(path).parent)
                filename = PurePosixPath(path).name
                
                parent = self.fs.get_node(parent_path)
                if isinstance(parent, Directory):
                    new_file = File(filename, parent=parent, content="", owner=self.username, group=self.username)
                    parent.add_child(new_file)
                else:
                    return "", f"touch: cannot touch '{arg}': No such file or directory\n", 1
                    
        return "", "", 0

class MkdirCommand(FileOpCommand):
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="mkdir", add_help=False)
        parser.add_argument("-p", "--parents", action="store_true")
        parser.add_argument("path", nargs="+")
        
        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1
            
        for path_str in parsed.path:
            resolved = self.emulator.resolve_path(path_str)
            
            if self.fs.exists(resolved):
                return "", f"mkdir: cannot create directory '{path_str}': File exists\n", 1
            
            # Simplified logic for -p
            if parsed.parents:
                # Recursive creation
                parts = [p for p in resolved.split("/") if p]
                current = self.fs.root
                for part in parts:
                    child = current.get_child(part)
                    if not child:
                        child = Directory(part, parent=current, owner=self.username, group=self.username)
                        current.add_child(child)
                    current = child
            else:
                parent_path = str(PurePosixPath(resolved).parent)
                dirname = PurePosixPath(resolved).name
                parent = self.fs.get_node(parent_path)
                
                if not parent or not isinstance(parent, Directory):
                    return "", f"mkdir: cannot create directory '{path_str}': No such file or directory\n", 1
                    
                new_dir = Directory(dirname, parent=parent, owner=self.username, group=self.username)
                parent.add_child(new_dir)
                
        return "", "", 0

class RmdirCommand(FileOpCommand):
    async def execute(self, args, input_data=""):
        if not args:
            return "", "rmdir: missing operand\n", 1
            
        for arg in args:
            path = self.emulator.resolve_path(arg)
            node = self.fs.get_node(path)
            
            if not node:
                 return "", f"rmdir: failed to remove '{arg}': No such file or directory\n", 1
            
            if not isinstance(node, Directory):
                 return "", f"rmdir: failed to remove '{arg}': Not a directory\n", 1
                 
            if node.children:
                 return "", f"rmdir: failed to remove '{arg}': Directory not empty\n", 1
                 
            # Remove
            node.parent.children.pop(node.name)
            
        return "", "", 0

class RmCommand(FileOpCommand):
    async def execute(self, args, input_data=""):
        recursive = "-r" in args or "-rf" in args or "-R" in args
        force = "-f" in args or "-rf" in args
        
        targets = [a for a in args if not a.startswith("-")]
        
        if not targets and not force:
             return "", "rm: missing operand\n", 1
             
        for arg in targets:
            path = self.emulator.resolve_path(arg)
            node = self.fs.get_node(path)
            
            if not node:
                if not force:
                    return "", f"rm: cannot remove '{arg}': No such file or directory\n", 1
                continue
                
            if isinstance(node, Directory) and not recursive:
                return "", f"rm: cannot remove '{arg}': Is a directory\n", 1
                
            # Remove
            if node.parent:
                node.parent.children.pop(node.name)
                
        return "", "", 0

class CpCommand(FileOpCommand):
    async def execute(self, args, input_data=""):
        if len(args) < 2:
             return "", "cp: missing file operand\n", 1
             
        # Naive implementation: assume last is dest, rest are sources
        # Ignoring flags for simplicity
        clean_args = [a for a in args if not a.startswith("-")]
        if len(clean_args) < 2:
            return "", "cp: missing destination file operand\n", 1
            
        dest_str = clean_args[-1]
        sources = clean_args[:-1]
        
        dest_path = self.emulator.resolve_path(dest_str)
        dest_node = self.fs.get_node(dest_path)
        
        dest_is_dir = isinstance(dest_node, Directory)
        
        for src_str in sources:
            src_path = self.emulator.resolve_path(src_str)
            src_node = self.fs.get_node(src_path)
            
            if not src_node:
                return "", f"cp: cannot stat '{src_str}': No such file or directory\n", 1
                
            if isinstance(src_node, Directory):
                # Need -r logic, skip for now
                return "", f"cp: -r not specified; omitting directory '{src_str}'\n", 1
            
            # Prepare content
            content = src_node.content
            
            if dest_is_dir:
                # Copy into directory
                new_name = src_node.name
                if dest_node.get_child(new_name):
                    # Overwrite
                    dest_node.get_child(new_name).content = content
                else:
                    new_file = File(new_name, parent=dest_node, content=content, owner=self.username, group=self.username)
                    dest_node.add_child(new_file)
            else:
                # Copy as dest name
                if dest_node: 
                    # Overwrite existing file
                    dest_node.content = content
                else:
                    # Create new file at dest path
                    parent_path = str(PurePosixPath(dest_path).parent)
                    filename = PurePosixPath(dest_path).name
                    parent = self.fs.get_node(parent_path)
                    
                    if not parent or not isinstance(parent, Directory):
                         return "", f"cp: cannot create regular file '{dest_str}': No such file or directory\n", 1
                         
                    new_file = File(filename, parent=parent, content=content, owner=self.username, group=self.username)
                    parent.add_child(new_file)

        return "", "", 0

class MvCommand(FileOpCommand):
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
                return "", f"mv: cannot stat '{src_str}': No such file or directory\n", 1
            
            # Unlink from old parent
            src_node.parent.children.pop(src_node.name)
            
            if dest_is_dir:
                 # Move into
                 target_name = src_node.name
                 if dest_node.get_child(target_name):
                      # Overwrite? usually yes.
                      dest_node.children.pop(target_name)
                 
                 src_node.parent = dest_node
                 src_node.name = target_name
                 dest_node.add_child(src_node)
            else:
                # Rename/Move to new path
                parent_path = str(PurePosixPath(dest_path).parent)
                target_name = PurePosixPath(dest_path).name
                parent = self.fs.get_node(parent_path)
                
                if not parent or not isinstance(parent, Directory):
                     return "", f"mv: cannot move '{src_str}' to '{dest_str}': No such file or directory\n", 1
                
                if parent.get_child(target_name):
                     # Overwrite existing dest file
                     parent.children.pop(target_name)
                     
                src_node.parent = parent
                src_node.name = target_name
                parent.add_child(src_node)
                
        return "", "", 0
