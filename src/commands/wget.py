import argparse
import aiohttp
import asyncio
from .base import Command
from pathlib import PurePosixPath

class WgetCommand(Command):
    """
    Fake wget command.
    Downloads files from the internet but saves them to a quarantine directory.
    Also creates a dummy file in the fake filesystem.
    """
    
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="wget", add_help=False)
        parser.add_argument("-O", "--output-document", dest="output_document", help="write documents to FILE")
        parser.add_argument("-q", "--quiet", action="store_true", help="quiet (no output)")
        parser.add_argument("url", nargs="?", help="URL to download")
        
        try:
             parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
             return "", "", 1

        if not parsed.url:
             return "", "wget: missing URL\n", 1
             
        url = parsed.url
        filename = parsed.output_document
        if not filename:
             filename = PurePosixPath(url).name
             if not filename:
                 filename = "index.html"
                 
        # Resolve target path in FakeFS
        full_path = self.emulator.resolve_path(filename)
        
        output_msg = ""
        if not parsed.quiet:
            output_msg += f"--2026-02-02 12:00:00--  {url}\n"
            output_msg += f"Resolving host... 1.2.3.4\n"
            output_msg += f"Connecting to host|1.2.3.4|:80... connected.\n"
            output_msg += "HTTP request sent, awaiting response... 200 OK\n"
            output_msg += "Length: 1234 (1.2K) [text/html]\n"
            output_msg += f"Saving to: '{filename}'\n\n"
        
        content = b""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status != 200:
                        return output_msg, f"ERROR {resp.status}: Not Found.\n", 8
                    
                    content = await resp.read()
                    
            # 1. Save to Quarantine (Real FS)
            if self.emulator.quarantine_callback:
                self.emulator.quarantine_callback(filename, content)
                
            # 2. Save to Fake FS
            # We save actual content to support `cat` later
            parent_dir = str(PurePosixPath(full_path).parent)
            base_name = PurePosixPath(full_path).name
            
            if not self.fs.exists(parent_dir):
                 return output_msg, f"{filename}: No such file or directory\n", 1
                 
            # Add file
            from core.filesystem_nodes import File, Directory
            parent_node = self.fs.get_node(parent_dir)
            if isinstance(parent_node, Directory):
                # Check overwrite?
                # Default behavior: overwrite for now
                if parent_node.get_child(base_name):
                    parent_node.get_child(base_name).content = content.decode('utf-8', errors='ignore')
                else:
                    new_file = File(base_name, parent=parent_node, content=content.decode('utf-8', errors='ignore'), owner=self.username, group=self.username)
                    parent_node.add_child(new_file)
            else: 
                 return output_msg, f"{filename}: Not a directory\n", 1

        except Exception as e:
            return output_msg, f"wget: error: {e}\n", 1

        if not parsed.quiet:
            output_msg += f"\n     0K ....                                      100% {len(content)}={len(content)/1024:.2f}K/s\n\n2026-02-02 12:00:00 ({filename}) - saved [{len(content)}/{len(content)}]\n"
            
        return output_msg, "", 0
