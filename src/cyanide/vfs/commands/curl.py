import argparse
from pathlib import PurePosixPath
from typing import Dict

import aiohttp

from .base import Command


class CurlCommand(Command):
    """
    Real implementation of curl.
    Downloads files from the internet.
    If output is a file, saves to both fake FS and quarantine.
    If output is stdout, prints to terminal but STILL saves to quarantine for analysis.
    """

    # Function 223: Executes the 'curl' command logic within the virtual filesystem.
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

        is_valid, error, resolved_ip = self.validate_url(url)
        if not is_valid:
            return "", f"curl: (1) {error}\n", 1

        request_url = url
        headers: Dict[str, str] = {}

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

        try:
            async with aiohttp.ClientSession() as session:
                if parsed.head:
                    async with session.head(request_url, headers=headers, timeout=10) as resp:
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

                        q_filename = (
                            filename if filename else PurePosixPath(url).name or "index.html"
                        )

                        if self.emulator.quarantine_callback:
                            self.emulator.quarantine_callback(q_filename, content)

                        if save_to_file:
                            full_path = self.emulator.resolve_path(filename)
                            parent_dir = str(PurePosixPath(full_path).parent)

                            if not self.fs.exists(parent_dir):
                                return (
                                    "",
                                    f"curl: (23) Failed writing body (0 != {len(content)})\n",
                                    23,
                                )

                            if (
                                self.fs.mkfile(
                                    full_path,
                                    content=content.decode("utf-8", errors="ignore"),
                                    owner=self.username,
                                )
                                is None
                            ):
                                return "", "curl: (23) Check output path\n", 23

                            if not parsed.silent:
                                stderr = f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100  {len(content)}  100  {len(content)}    0     0   {len(content)}      0 --:--:-- --:--:-- --:--:--  {len(content)}\n"
                                return "", stderr, 0
                            return "", "", 0

                        else:
                            return content.decode("utf-8", errors="ignore"), "", 0

        except aiohttp.ClientError as e:
            return "", f"curl: (6) Could not resolve host: {e}\n", 6
        except Exception as e:
            return "", f"curl: (1) Protocol not supported or error: {e}\n", 1

        return "", "", 0
