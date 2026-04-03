import re
from urllib.parse import urlparse


class ContextAnalyzer:
    """
    Component 2: Context Analyzer
    Analyzes URLs and sensitive file paths to increase risk score.
    """

    def __init__(self):
        self.whitelist = {
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "pypi.org",
            "npmjs.com",
            "rubygems.org",
            "docker.com",
            "docker.io",
            "quay.io",
            "ubuntu.com",
            "debian.org",
            "centos.org",
            "fedoraproject.org",
            "google.com",
            "microsoft.com",
            "amazon.com",
            "cloudflare.com",
        }

        self.suspicious_tlds = {
            ".xyz",
            ".top",
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq",
            ".pw",
            ".cc",
            ".ws",
            ".info",
            ".click",
            ".loan",
            ".ru",
            ".cn",
        }

        self.url_keywords = {
            "malware",
            "exploit",
            "payload",
            "backdoor",
            "rootkit",
            "trojan",
            "rat",
            "miner",
            "botnet",
            "ransomware",
            "reverse",
            "shell",
            "c2",
            "exfil",
            "hack",
        }

        self.sensitive_paths = {
            "/etc/shadow": {"severity": "CRITICAL", "technique": "T1003.008"},
            "/etc/passwd": {"severity": "MEDIUM", "technique": "T1087.001"},
            "/root/.ssh": {"severity": "HIGH", "technique": "T1552.004"},
            ".ssh/id_rsa": {"severity": "HIGH", "technique": "T1552.004"},
            ".ssh/authorized_keys": {"severity": "HIGH", "technique": "T1098.004"},
            ".bash_history": {"severity": "MEDIUM", "technique": "T1552.003"},
            "/var/log": {"severity": "MEDIUM", "technique": "T1070"},
            "/etc/crontab": {"severity": "HIGH", "technique": "T1053.003"},
        }

    def analyze_url(self, command: str) -> dict:
        """
        Analyzes URLs in command.
        Returns: {has_url, risk_score, verdict, flags, urls}
        """
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', command)
        if not urls:
            return {"has_url": False, "risk_score": 0.0, "verdict": "safe", "flags": []}

        risk_score = 0.0
        flags = []

        for url in urls:
            u_score, u_flags = self._analyze_single_url(url)
            risk_score += u_score
            flags.extend(u_flags)

        risk_score = max(0.0, min(1.0, risk_score))
        return {
            "has_url": True,
            "urls": urls,
            "risk_score": risk_score,
            "flags": list(set(flags)),
            "verdict": "suspicious" if risk_score >= 0.4 else "safe",
        }

    def _analyze_single_url(self, url: str) -> tuple[float, list[str]]:
        """Analyzes a single URL and returns its risk score and flags."""
        if not url.startswith("http"):
            url = "https://" + url

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(":")[0]

            if self._is_safe_domain(domain):
                return -0.3, []

            return self._check_suspicious_url(url, domain)

        except Exception:
            return 0.0, []

    def _is_safe_domain(self, domain: str) -> bool:
        """Check if a domain is whitelisted."""
        for safe_dom in self.whitelist:
            if domain == safe_dom or domain.endswith("." + safe_dom):
                return True
        return False

    def _check_suspicious_url(self, url: str, domain: str) -> tuple[float, list[str]]:
        """Check for suspicious attributes in a non-whitelisted URL."""
        score = 0.0
        flags = []

        if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
            score += 0.4
            flags.append(f"IP-based URL: {domain}")

        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                score += 0.5
                flags.append(f"Suspicious TLD: {tld}")
                break

        for kw in self.url_keywords:
            if kw in url.lower():
                score += 0.4
                flags.append(f"Suspicious keyword: {kw}")
                break

        return score, flags

    def analyze_file_paths(self, command: str) -> dict:
        """
        Analyzes sensitive file paths.
        Returns: {matched, paths, severity, techniques}
        """
        matched_paths = []
        techniques = set()
        max_severity = 0
        sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

        for path, info in self.sensitive_paths.items():
            if path in command:
                matched_paths.append(path)
                techniques.add(info["technique"])
                max_severity = max(max_severity, sev_map.get(info["severity"], 0))

        if not matched_paths:
            return {"matched": False}

        rev_sev_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}

        return {
            "matched": True,
            "paths": matched_paths,
            "severity": rev_sev_map.get(max_severity, "LOW"),
            "techniques": list(techniques),
            "verdict": "suspicious",
        }
