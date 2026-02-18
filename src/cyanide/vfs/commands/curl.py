import argparse
from typing import Dict
from pathlib import PurePosixPath

import aiohttp

from .base import Command


class CurlCommand(Command):
    """
    Real implementation of curl.
    Downloads files from the internet.
    If output is a file, saves to both fake FS and quarantine.
    If output is stdout, prints to terminal but STILL saves to quarantine for analysis.
    """

    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="curl", add_help=False)
        parser.add_argument("-o", "--output", dest="output", help="write to file")
        parser.add_argument(
            "-O", "--remote-name", action="store_true", help="write to file named like remote file"
        )
        parser.add_argument("-I", "--head", action="store_true", help="show headers only")
        parser.add_argument("-s", "--silent", action="store_true", help="silent mode")
        parser.add_argument("url", nargs="?", help="URL to fetch")

        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1

        url = parsed.url
        if not url:
            if unknown:
                url = unknown[-1]
            else:
                return "", "curl: try 'curl --help' for more information\n", 1

        # Security: Validate URL
        is_valid, error, resolved_ip = self.validate_url(url)
        if not is_valid:
            return "", f"curl: (1) {error}\n", 1

        # Use host for request to allow SNI/SSL verification
        request_url = url
        headers: Dict[str, str] = {}
        # We obtained resolved_ip during validation but we don't force it in URL
        # aiohttp will resolve it again, which is fine for now to fix SSL

        # Determine output mode
        save_to_file = False
        filename = None

        if parsed.output:
            save_to_file = True
            filename = parsed.output
        elif parsed.remote_name:
            save_to_file = True
            filename = PurePosixPath(url).name
            if not filename:
                filename = "index.html"

        # Execute Request
        try:
            async with aiohttp.ClientSession() as session:
                if parsed.head:
                    async with session.head(request_url, headers=headers, timeout=10) as resp:
                        # Format headers like curl
                        version_str = "1.1"
                        if resp.version:
                            version_str = f"{resp.version.major}.{resp.version.minor}"
                        headers_out = f"HTTP/{version_str} {resp.status} {resp.reason}\r\n"
                        for k, v in resp.headers.items():
                            headers_out += f"{k}: {v}\r\n"
                        headers_out += "\r\n"
                        return headers_out, "", 0
                else:
                    async with session.get(request_url, headers=headers, timeout=10) as resp:
                        if resp.status >= 400:
                            if not parsed.silent:
                                return (
                                    "",
                                    f"curl: (22) The requested URL returned error: {resp.status}\n",
                                    22,
                                )
                            return "", "", 22

                        content = await resp.read()

                        # ALWAYs save to Quarantine (Real FS) for analysis
                        # We use a temp name if we don't have a filename yet, or derive it from URL
                        q_filename = (
                            filename if filename else PurePosixPath(url).name or "index.html"
                        )

                        if self.emulator.quarantine_callback:
                            self.emulator.quarantine_callback(q_filename, content)

                        # Output handling
                        if save_to_file:
                            # Save to Fake FS
                            full_path = self.emulator.resolve_path(filename)
                            parent_dir = str(PurePosixPath(full_path).parent)
                            base_name = PurePosixPath(full_path).name

                            if not self.fs.exists(parent_dir):
                                return (
                                    "",
                                    f"curl: (23) Failed writing body (0 != {len(content)})\n",
                                    23,
                                )

                            from cyanide.vfs.nodes import Directory, File

                            parent_node = self.fs.get_node(parent_dir)

                            if isinstance(parent_node, Directory):
                                # Overwrite logic
                                if parent_node.get_child(base_name):
                                    parent_node.get_child(base_name).content = content.decode(
                                        "utf-8", errors="ignore"
                                    )
                                else:
                                    new_file = File(
                                        base_name,
                                        parent=parent_node,
                                        content=content.decode("utf-8", errors="ignore"),
                                        owner=self.username,
                                        group=self.username,
                                    )
                                    parent_node.add_child(new_file)
                            else:
                                return "", "curl: (23) Check output path\n", 23

                            if not parsed.silent:
                                # Curl progress meter simulation (simplified)
                                stderr = f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100  {len(content)}  100  {len(content)}    0     0   {len(content)}      0 --:--:-- --:--:-- --:--:--  {len(content)}\n"
                                return "", stderr, 0
                            return "", "", 0

                        else:
                            # Print to stdout
                            return content.decode("utf-8", errors="ignore"), "", 0

        except aiohttp.ClientError as e:
            return "", f"curl: (6) Could not resolve host: {e}\n", 6
        except Exception as e:
            return "", f"curl: (1) Protocol not supported or error: {e}\n", 1

        return "", "", 0
