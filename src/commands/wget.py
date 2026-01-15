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
    def __init__(self, shell):
        super().__init__(shell)
        self.parser = argparse.ArgumentParser(prog="wget", add_help=False)
        self.parser.add_argument("-O", "--output-document", dest="output_document", help="write documents to FILE")
        self.parser.add_argument("-q", "--quiet", action="store_true", help="quiet (no output)")
        self.parser.add_argument("url", nargs="?", help="URL to download")

    def execute(self, args):
        # We need async execution, but the BaseCommand is synchronous.
        # However, the shell emulator calls us in an async context? 
        # Actually shell.execute is synchronous in the current design (see shell_emulator.py).
        # But we are running in an async event loop (Telnet/SSH handlers).
        # We should probably refactor ShellEmulator to be async or use run_until_complete?
        # WAIT: The commands are currently synchronous. 
        # But `wget` creates network traffic. 
        # Blocking the event loop is bad.
        # Ideally, we should change `ShellEmulator.execute` to be `async def execute`.
        # Let's check `shell_emulator.py` again.
        
        # It is synchronous: `def execute(self, command_line: str) -> tuple[str, str, int]:`
        # And `handle_telnet` calls it: `stdout, stderr, rc = shell.execute(cmd)`
        # `handle_telnet` IS async.
        
        # CRITICAL REFRACTOR needed: Make ShellEmulator async to support network commands properly.
        # But for now, to avoid breaking everything, I might have to run the download synchronously 
        # OR use a hack.
        # Actually, `requests` is sync. `aiohttp` is async.
        # If I use `requests`, I block the whole server for one user download. Bad.
        # If I use `aiohttp`, I need `await`.
        
        # Checking `server.py`:
        # `stdout, stderr, rc = shell.execute(cmd)`
        # I should update ShellEmulator to be async. 
        # But I should do it in a way that minimal changes are needed.
        
        # Let's see if I can make `execute` async in `WgetCommand` and handle it in `ShellEmulator`.
        # If I change `ShellEmulator.execute` to `async`, I need to update all call sites.
        # `server.py`: `handle_telnet` and `SSHSession`.
        
        # Decision: I will assume I can make `ShellEmulator` async. It's the right way.
        pass

# I will write the file assuming async structure, and then I'll update ShellEmulator and Server.
import asyncio

class WgetCommand(Command): # Changed from BaseCommand to Command to match the first definition
    def __init__(self, shell):
        super().__init__(shell)
        self.emulator = shell # Explicitly store the shell as emulator
        self.parser = argparse.ArgumentParser(prog="wget", add_help=False)
        self.parser.add_argument("-O", "--output-document", dest="output_document", help="write documents to FILE")
        self.parser.add_argument("-q", "--quiet", action="store_true", help="quiet (no output)")
        self.parser.add_argument("url", nargs="?", help="URL to download")

    async def execute_async(self, args): # New async entry point
        try:
            parsed, unknown = self.parser.parse_known_args(args)
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
            output_msg += f"--2024-01-01 12:00:00--  {url}\n"
            output_msg += f"Resolving {PurePosixPath(url).parts[1] if len(PurePosixPath(url).parts)>1 else 'host'}... 1.2.3.4\n"
            output_msg += f"Connecting to {PurePosixPath(url).parts[1] if len(PurePosixPath(url).parts)>1 else 'host'}|1.2.3.4|:80... connected.\n"
            output_msg += "HTTP request sent, awaiting response... 200 OK\n"
            output_msg += "Length: 1234 (1.2K) [text/html]\n"
            output_msg += f"Saving to: '{filename}'\n\n"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status != 200:
                        return output_msg, f"ERROR 404: Not Found.\n", 8
                    
                    content = await resp.read()
                    
            # 1. Save to Quarantine (Real FS)
            # We need to access the HoneypotServer instance to get the quarantine path?
            # ShellEmulator has `fs` but not `server`.
            # We might need to pass `server` or `quarantine_path` to Shell... 
            # Or just hack it: `self.shell.fs` -> doesn't help.
            # I should update ShellEmulator to hold a reference to the Server or Quarantine callback.
            # For now, I'll rely on a callback I'll add to ShellEmulator.
            
            if hasattr(self.emulator, 'quarantine_callback'):
                self.emulator.quarantine_callback(filename, content)
                
            # 2. Save to Fake FS
            # Just create a dummy file with realistic size?
            # Or save actual content? 
            # Saving actual content is better for `cat` later.
            parent_dir = str(PurePosixPath(full_path).parent)
            base_name = PurePosixPath(full_path).name
            
            # Helper to navigate and create file
            # Self.shell.fs.get_node(parent_dir) ...
            
            # We can use the internal `mkfile` logic if we expose it, or just:
            try:
                # We need to ensure parent exists
                if not self.emulator.fs.exists(parent_dir):
                     return output_msg, f"{filename}: No such file or directory\n", 1
                     
                # Add file
                from ..core.filesystem_nodes import File, Directory
                parent_node = self.emulator.fs.get_node(parent_dir)
                if isinstance(parent_node, Directory):
                    # Check overwrite?
                    # Wget usually overwrites or adds .1
                    # default behavior: overwrite for now
                    new_file = File(base_name, parent=parent_node, content=content.decode('utf-8', errors='ignore'), owner=self.emulator.username, group=self.emulator.username)
                    parent_node.add_child(new_file)
                else: 
                     return output_msg, f"{filename}: Not a directory\n", 1

            except Exception as e:
                return output_msg, f"Error writing to FS: {e}\n", 1

        except Exception as e:
            return output_msg, f"wget: error: {e}\n", 1

        if not parsed.quiet:
            output_msg += f"\n     0K ....                                      100% 1.23M=0.001s\n\n2024-01-01 12:00:00 ({filename}) - saved [1234/1234]\n"
            
        return output_msg, "", 0

    def execute(self, args):
        # Fallback for sync calls, should not be used if we update ShellEmulator correctly.
        return "", "Internal Error: Async required\n", 1
