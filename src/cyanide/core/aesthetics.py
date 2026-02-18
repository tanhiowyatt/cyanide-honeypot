from pathlib import Path

# ANSI Color Codes
CLR_LOGO = "\033[1;37m"  # Bold White
CLR_USER = "\033[1;32m"  # Bold Green
CLR_SEP = "\033[0m"  # Reset
CLR_KEY = "\033[1;33m"  # Bold Yellow
CLR_VAL = "\033[0m"  # Reset
RESET = "\033[0m"


def print_startup_banner(config):
    """Print logo and startup information in a dynamic colored fastfetch-style layout."""
    root_dir = Path.cwd()
    logo_path = root_dir / "assets/branding/logo.txt"

    # 1. Read Logo ASCII
    logo_lines = []
    if logo_path.exists():
        try:
            # Wrap logo in color
            logo_raw = logo_path.read_text().splitlines()
            logo_lines = [f"{CLR_LOGO}{line}{RESET}" for line in logo_raw]
        except Exception:
            pass

    if not logo_lines or not config:
        return

    # 2. Gather Dynamic Information
    hostname = config.get("hostname", "cyanide")
    user_host = f"{CLR_USER}root@{hostname}{RESET}"
    separator = f"{CLR_SEP}{'-' * (len('root@') + len(hostname))}{RESET}"

    def fmt_key(k):
        return f"{CLR_KEY}{k}{RESET}"

    info_fields = [
        user_host,
        separator,
        f"{fmt_key('OS:')} Cyanide Honeypot ({config.get('os_profile', 'random')})",
        f"{fmt_key('Hostname:')} {config.get('hostname', 'server01')}",
        f"{fmt_key('Listen IP:')} {config.get('listen_ip', '0.0.0.0')}",
        f"{fmt_key('SSH:')} {config.get('ssh', {}).get('port', 2222)}",
        f"{fmt_key('Telnet:')} {config.get('telnet', {}).get('port', 2323)}",
        f"{fmt_key('Metrics:')} {config.get('metrics', {}).get('port', 9090)} ({'enabled' if config.get('metrics', {}).get('enabled') else 'disabled'})",
        f"{fmt_key('ML Filter:')} {'Enabled' if config.get('ml', {}).get('enabled') else 'Disabled'}",
        f"{fmt_key('Sessions:')} {config.get('max_sessions', 100)} max ({config.get('max_sessions_per_ip', 5)} per IP)",
        f"{fmt_key('Timeout:')} {config.get('session_timeout', 300)}s",
        f"{fmt_key('Quarantine:')} {config.get('quarantine_max_size_mb', 500)}MB max",
    ]

    # 3. Print Side-by-Side
    print()  # Leading newline
    max_h = max(len(logo_lines), len(info_fields))
    # Calculate width based on raw logo lines (without ANSI codes)
    raw_logo_lines = logo_path.read_text().splitlines()
    logo_width = max(len(line) for line in raw_logo_lines) + 4

    for i in range(max_h):
        r_part = info_fields[i] if i < len(info_fields) else ""

        # When padding l_part, we need to account for hidden ANSI characters
        # Or just pad the raw line and then wrap in color?
        # Let's pad the raw line for correct alignment
        raw_l = raw_logo_lines[i] if i < len(raw_logo_lines) else ""
        padded_raw_l = f"{raw_l:<{logo_width}}"
        # Wrap the whole padded part in logo color
        colored_l = f"{CLR_LOGO}{padded_raw_l}{RESET}"

        print(f"{colored_l}{r_part}")

    print()  # Trailing newline
