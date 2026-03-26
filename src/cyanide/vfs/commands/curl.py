import argparse
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

    # Function 223: Executes the 'curl' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        """Execute the curl command."""
        parsed, unknown = self._parse_curl_args(args)
        url = self._get_url(parsed, unknown)
        if not url:
            return "", "curl: try 'curl --help' for more information\n", 1

        is_valid, error, resolved_ip = self.validate_url(url)

        # ML: C2/DGA intelligence
        if self.emulator.logger:
            self.emulator.logger.log_event(
                self.emulator.session_id,
                "curl_url_resolve",
                {
                    "src_ip": self.emulator.src_ip,
                    "url": url,
                    "resolved_ip": resolved_ip or "unresolved",
                    "is_valid": is_valid,
                },
            )

        if not is_valid:
            return "", f"curl: (1) {error}\n", 1

        save_to_file, filename = self._get_output_config(url, parsed)

        try:
            async with aiohttp.ClientSession() as session:
                if parsed.head:
                    async with session.head(url, headers={}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        return self._handle_head_response(resp), "", 0

                async with session.get(url, headers={}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status >= 400:
                        err_msg = (
                            ""
                            if parsed.silent
                            else f"curl: (22) The requested URL returned error: {resp.status}\n"
                        )
                        return "", err_msg, 22

                    content = await resp.read()
                    q_filename = filename if filename else PurePosixPath(url).name or "index.html"
                    if self.emulator.quarantine_callback:
                        self.emulator.quarantine_callback(q_filename, content)

                    if save_to_file:
                        return self._handle_file_save(filename, content, parsed.silent)

                    return content.decode("utf-8", errors="ignore"), "", 0

        except aiohttp.ClientError as e:
            return "", f"curl: (6) Could not resolve host: {e}\n", 6
        except Exception as e:
            return "", f"curl: (1) Protocol not supported or error: {e}\n", 1

    def _parse_curl_args(self, args):
        """Parse curl arguments."""
        parser = argparse.ArgumentParser(prog="curl", add_help=False)
        parser.add_argument("-o", "--output", dest="output", help="write to file")
        parser.add_argument(
            "-O", "--remote-name", action="store_true", help="write to file named like remote file"
        )
        parser.add_argument("-I", "--head", action="store_true", help="show headers only")
        parser.add_argument("-s", "--silent", action="store_true", help="silent mode")
        parser.add_argument("url", nargs="?", help="URL to fetch")

        try:
            return parser.parse_known_args(args)
        except SystemExit:
            if self.emulator.logger:
                self.emulator.logger.log_event(
                    self.emulator.session_id,
                    "curl_parse_fail",
                    {"src_ip": self.emulator.src_ip, "full_cmd": " ".join(args)},
                )
            raise

    def _get_url(self, parsed, unknown):
        """Extract URL from parsed or unknown args."""
        if parsed.url:
            return parsed.url
        if unknown:
            return unknown[-1]
        return None

    def _get_output_config(self, url, parsed):
        """Determine if saving to file and the filename."""
        if parsed.output:
            return True, parsed.output
        if parsed.remote_name:
            filename = PurePosixPath(url).name or "index.html"
            return True, filename
        return False, None

    def _handle_head_response(self, resp):
        """Format header output for HEAD requests."""
        version_str = f"{resp.version.major}.{resp.version.minor}" if resp.version else "1.1"
        headers_out = f"HTTP/{version_str} {resp.status} {resp.reason}\r\n"
        for k, v in resp.headers.items():
            headers_out += f"{k}: {v}\r\n"
        headers_out += "\r\n"
        return headers_out

    def _handle_file_save(self, filename, content, silent):
        """Save content to fake FS and return result."""
        full_path = self.emulator.resolve_path(filename)
        parent_dir = str(PurePosixPath(full_path).parent)

        if not self.fs.exists(parent_dir):
            return "", f"curl: (23) Failed writing body (0 != {len(content)})\n", 23

        if (
            self.fs.mkfile(
                full_path, content=content.decode("utf-8", errors="ignore"), owner=self.username
            )
            is None
        ):
            return "", "curl: (23) Check output path\n", 23

        if not silent:
            stderr = (
                "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                f"100  {len(content)}  100  {len(content)}    0     0   {len(content)}      0 --:--:-- --:--:-- --:--:--  {len(content)}\n"
            )
            return "", stderr, 0
        return "", "", 0
