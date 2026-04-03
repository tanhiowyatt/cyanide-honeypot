from pathlib import Path

CLR_LOGO = "\033[1;37m"
CLR_USER = "\033[1;32m"
CLR_SEP = "\033[0m"
CLR_KEY = "\033[1;33m"
CLR_VAL = "\033[0m"
RESET = "\033[0m"


def _get_logo_raw():
    logo_path = Path.cwd() / "assets/branding/logo.txt"
    if logo_path.exists():
        try:
            return logo_path.read_text().splitlines()
        except Exception:
            pass
    return []


def _get_service_status(config, service, default_port):
    svc_config = config.get(service, {})
    port = svc_config.get("port", default_port)
    enabled = "enabled" if svc_config.get("enabled") else "disabled"
    return f"{port} ({enabled})"


def fmt_key(k):
    return f"{CLR_KEY}{k}{RESET}"
def print_startup_banner(config, resolved_profile: str = ""):
    """Print logo and startup information in a dynamic colored fastfetch-style layout."""
    logo_raw = _get_logo_raw()

    if not logo_raw or not config:
        return

    hostname = config.get("hostname", "cyanide")
    user_host = f"{CLR_USER}root@{hostname}{RESET}"
    separator = f"{CLR_SEP}{'-' * (len('root@') + len(hostname))}{RESET}"

    info_fields = [
        user_host,
        separator,
        f"{fmt_key('OS:')} Cyanide Honeypot ({resolved_profile or config.get('os_profile', 'random')})",
        f"{fmt_key('Hostname:')} {config.get('hostname', 'server01')}",
        f"{fmt_key('Listen IP:')} {config.get('listen_ip', '0.0.0.0')}",
        f"{fmt_key('SSH:')} {config.get('ssh', {}).get('port', 2222)}",
        f"{fmt_key('Telnet:')} {_get_service_status(config, 'telnet', 2323)}",
        f"{fmt_key('SMTP:')} {_get_service_status(config, 'smtp', 2525)}",
        f"{fmt_key('Metrics:')} {_get_service_status(config, 'metrics', 9090)}",
        f"{fmt_key('ML Filter:')} {'Enabled' if config.get('ml', {}).get('enabled') else 'Disabled'}",
        f"{fmt_key('Sessions:')} {config.get('max_sessions', 100)} max ({config.get('max_sessions_per_ip', 5)} per IP)",
        f"{fmt_key('Timeout:')} {config.get('session_timeout', 300)}s",
        f"{fmt_key('Quarantine:')} {config.get('quarantine_max_size_mb', 500)}MB max",
    ]

    print()
    max_h = max(len(logo_raw), len(info_fields))
    logo_width = max(len(line) for line in logo_raw) + 4 if logo_raw else 0

    for i in range(max_h):
        r_part = info_fields[i] if i < len(info_fields) else ""

        raw_l = logo_raw[i] if i < len(logo_raw) else ""
        padded_raw_l = f"{raw_l:<{logo_width}}"
        colored_l = f"{CLR_LOGO}{padded_raw_l}{RESET}"

        print(f"{colored_l}{r_part}")

    print()
