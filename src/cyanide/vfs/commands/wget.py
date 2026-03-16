import argparse
from pathlib import PurePosixPath
from typing import Dict

import aiohttp

from .base import Command


class WgetCommand(Command):
    """
    Fake wget command.
    Downloads files from the internet but saves them to a quarantine directory.
    Also creates a dummy file in the fake filesystem.
    """

    # Function 276: Executes the 'wget' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        parser = argparse.ArgumentParser(prog="wget", add_help=False)
        parser.add_argument(
            "-O", "--output-document", dest="output_document", help="write documents to FILE"
        )
        parser.add_argument("-q", "--quiet", action="store_true", help="quiet (no output)")
        parser.add_argument("url", nargs="?", help="URL to download")

        try:
            parsed, unknown = parser.parse_known_args(args)
        except SystemExit:
            return "", "", 1

        if not parsed.url:
            return "", "wget: missing URL\n", 1

        is_valid, error, resolved_ip = self.validate_url(parsed.url)
        if not is_valid:
            return "", f"wget: error: {error}\n", 1

        url = parsed.url
        request_url = url
        headers: Dict[str, str] = {}
        filename = parsed.output_document
        if not filename:
            filename = PurePosixPath(url).name
            if not filename:
                filename = "index.html"

        full_path = self.emulator.resolve_path(filename)

        output_msg = ""
        if not parsed.quiet:
            output_msg += f"--2026-02-02 12:00:00--  {url}\n"
            output_msg += "Resolving host... 1.2.3.4\n"
            output_msg += "Connecting to host|1.2.3.4|:80... connected.\n"
            output_msg += "HTTP request sent, awaiting response... 200 OK\n"
            output_msg += "Length: 1234 (1.2K) [text/html]\n"
            output_msg += f"Saving to: '{filename}'\n\n"

        content = b""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(request_url, headers=headers, timeout=10) as resp:
                    if resp.status != 200:
                        return output_msg, f"ERROR {resp.status}: Not Found.\n", 8

                    content = await resp.read()

            if self.emulator.quarantine_callback:
                self.emulator.quarantine_callback(filename, content)

            if (
                self.fs.mkfile(
                    full_path,
                    content=content.decode("utf-8", errors="ignore"),
                    owner=self.username,
                    group=self.username,
                )
                is None
            ):
                return output_msg, f"{filename}: error creating file in VFS\n", 1

        except Exception as e:
            import traceback

            traceback.print_exc()
            return output_msg, f"wget: error: {str(e)}\n", 1

        if not parsed.quiet:
            output_msg += f"\n     0K ....                                      100% {len(content)}={len(content)/1024:.2f}K/s\n\n2026-02-02 12:00:00 ({filename}) - saved [{len(content)}/{len(content)}]\n"

        return output_msg, "", 0
