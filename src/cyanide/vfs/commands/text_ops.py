import argparse
from .base import Command

class TextOpCommand(Command):
    """Base for text operations."""
    pass

class GrepCommand(TextOpCommand):
    async def execute(self, args, input_data=""):
        # Improved grep: supports -i, -v
        parser = argparse.ArgumentParser(prog="grep", add_help=False)
        parser.add_argument("-i", "--ignore-case", action="store_true")
        parser.add_argument("-v", "--invert-match", action="store_true")
        parser.add_argument("pattern", nargs="?")
        parser.add_argument("files", nargs="*")
        
        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1
            
        pattern = parsed.pattern
        if not pattern:
             return "", "Usage: grep [OPTION]... PATTERN [FILE]...\n", 2
             
        files = parsed.files
        ignore_case = parsed.ignore_case
        invert_match = parsed.invert_match
        
        lines = []
        if not files:
            lines = input_data.splitlines(keepends=True)
        else:
            for f in files:
                path = self.emulator.resolve_path(f)
                if self.fs.is_file(path):
                     content = self.fs.get_content(path)
                     lines.extend(content.splitlines(keepends=True))
                elif self.fs.is_dir(path):
                     return "", f"grep: {f}: Is a directory\n", 2
        
        output = ""
        search_pattern = pattern.lower() if ignore_case else pattern
        
        for line in lines:
            search_line = line.lower() if ignore_case else line
            match = search_pattern in search_line
            
            if invert_match:
                if not match:
                    output += line
            else:
                if match:
                    output += line
                
        rc = 0 if output else 1
        return output, "", rc

class HeadCommand(TextOpCommand):
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="head", add_help=False)
        parser.add_argument("-n", "--lines", type=int, default=10)
        parser.add_argument("files", nargs="*")
        
        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1
            
        count = parsed.lines
        files = parsed.files
        
        lines = []
        if not files:
            lines = input_data.splitlines(keepends=True)
        else:
            path = self.emulator.resolve_path(files[0])
            if self.fs.is_file(path):
                 lines = self.fs.get_content(path).splitlines(keepends=True)
                 
        return "".join(lines[:count]), "", 0

class TailCommand(TextOpCommand):
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="tail", add_help=False)
        parser.add_argument("-n", "--lines", type=int, default=10)
        parser.add_argument("files", nargs="*")
        
        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1
            
        count = parsed.lines
        files = parsed.files

        lines = []
        if not files:
             lines = input_data.splitlines(keepends=True)
        else:
             path = self.emulator.resolve_path(files[0])
             if self.fs.is_file(path):
                  lines = self.fs.get_content(path).splitlines(keepends=True)
                  
        return "".join(lines[-count:]), "", 0
