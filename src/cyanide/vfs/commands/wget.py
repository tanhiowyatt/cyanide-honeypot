import argparse
from pathlib import PurePosixPath

import aiohttp

from .base import Command


class WgetCommand(Command):
    """
    Fake wget command.
    Downloads files from the internet but saves them to a quarantine directory.
    Also creates a dummy file in the fake filesystem.
    """

    async def execute(self, args, input_data=""):
        parser = self._prepare_parser()

        try:
            parsed, unknown = parser.parse_known_args(args)
            if unknown:
                self._log_event(
                    "wget_unknown_args",
                    {
                        "url": getattr(parsed, "url", None),
                        "unknown_args": unknown,
                        "full_cmd": " ".join(args),
                    },
                )
        except SystemExit:
            self._log_event("wget_parse_fail", {"full_cmd": " ".join(args)})
            raise

        if not parsed.url:
            return "", "wget: missing URL\n", 1

        is_valid, error, resolved_ip = self.validate_url(parsed.url)
        self._log_event(
            "wget_url_resolve",
            {"url": parsed.url, "resolved_ip": resolved_ip or "unresolved", "is_valid": is_valid},
        )

        if not is_valid:
            return "", f"wget: error: {error}\n", 1

        return await self._handle_download(parsed, resolved_ip)

    def _prepare_parser(self):
        parser = argparse.ArgumentParser(prog="wget", add_help=False)
        parser.add_argument("-O", "--output-document", dest="output_document")
        parser.add_argument("-q", "--quiet", action="store_true")
        parser.add_argument("url", nargs="?")
        return parser

    def _log_event(self, event_type, data):
        if self.emulator.logger:
            data["src_ip"] = self.emulator.src_ip
            self.emulator.logger.log_event(self.emulator.session_id, event_type, data)

    async def _handle_download(self, parsed, resolved_ip):
        url = parsed.url
        filename = parsed.output_document or PurePosixPath(url).name or "index.html"
        full_path = self.emulator.resolve_path(filename)

        output_msg = self._generate_header(url, resolved_ip, filename) if not parsed.quiet else ""

        try:
            content = await self._download_file(url)
            if self.emulator.quarantine_callback:
                self.emulator.quarantine_callback(filename, content)

            if (
                self.fs.mkfile(
                    full_path, content=content.decode("utf-8", errors="ignore"), owner=self.username
                )
                is None
            ):
                return output_msg, f"{filename}: error creating file in VFS\n", 1

            if not parsed.quiet:
                output_msg += self._generate_footer(content, filename)
            return output_msg, "", 0
        except Exception as e:
            return output_msg, f"wget: error: {str(e)}\n", 1

    def _generate_header(self, url, resolved_ip, filename):
        msg = f"--2026-02-02 12:00:00--  {url}\n"
        msg += f"Resolving host... {resolved_ip or '1.2.3.4'}\n"
        msg += "Connecting to host|1.2.3.4|:80... connected.\n"
        msg += "HTTP request sent, awaiting response... 200 OK\n"
        msg += "Length: 1234 (1.2K) [text/html]\n"
        msg += f"Saving to: '{filename}'\n\n"
        return msg

    def _generate_footer(self, content, filename):
        return (
            f"\n     0K ....                                      100% "
            f"{len(content)}={len(content)/1024:.2f}K/s\n\n"
            f"2026-02-02 12:00:00 ({filename}) - saved [{len(content)}/{len(content)}]\n"
        )

    async def _download_file(self, url):
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP {resp.status}")
                return await resp.read()
