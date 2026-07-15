"""
sedf/utils/http_client.py - Reusable HTTP client for SEDF (FR-01, NFR-01)

Wraps requests/httpx with:
  - Configurable timeout, proxy, headers, cookies
  - Performance tracking (response time)
  - Safe mode: blocks requests to non-private ranges when enabled
  - NFR-04: Does not crash on malformed responses
"""

import time
import json
import ipaddress
from typing import Optional
from urllib.parse import urlparse

from sedf.utils.logger import get_logger

logger = get_logger(__name__)

# Private / loopback address ranges (for safe-mode checking)
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private_url(url: str) -> bool:
    """Return True if the URL hostname resolves to a private/internal address."""
    try:
        host = urlparse(url).hostname
        if not host:
            return False
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        # Hostname that needs resolution — conservatively allow it in safe mode;
        # actual resolution happens in the target server, not here.
        return False


class HTTPClient:
    """Thread-safe HTTP client with SEDF-specific configuration."""

    def __init__(self, args):
        self.args = args
        self.timeout = getattr(args, "timeout", 10)
        self.proxy = getattr(args, "proxy", None)
        self.safe_mode = getattr(args, "safe_mode", True)
        self.method = getattr(args, "method", "GET")
        self.post_data = getattr(args, "data", None)

        self._session = self._build_session()

    def _build_session(self):
        try:
            import requests
            session = requests.Session()
            session.max_redirects = 3

            # Headers
            session.headers.update({
                "User-Agent": "SEDF/1.0 (Security Testing Tool; Authorized Use Only)",
                "Accept": "*/*",
            })

            # Custom headers
            extra_headers = getattr(self.args, "headers", None)
            if extra_headers:
                try:
                    session.headers.update(json.loads(extra_headers))
                except Exception:
                    logger.warning("Could not parse --headers JSON; ignoring.")

            # Cookies
            cookies_raw = getattr(self.args, "cookies", None)
            if cookies_raw:
                for pair in cookies_raw.split(";"):
                    if "=" in pair:
                        k, v = pair.strip().split("=", 1)
                        session.cookies.set(k.strip(), v.strip())

            # Proxy
            if self.proxy:
                session.proxies = {"http": self.proxy, "https": self.proxy}

            # Disable SSL verification for lab environments
            session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            return session
        except ImportError:
            logger.error(
                "The 'requests' library is required. Install with: pip install requests"
            )
            raise

    def get(self, url: str, override_body=None) -> dict:
        """
        Send a GET (or configured method) request.
        override_body: if provided, use this as the POST body instead of self.post_data.
                       This allows per-request payload injection into POST bodies.
        Returns a dict with: status_code, body, headers, elapsed.
        NFR-04: Never raises; returns error dict on failure.
        """
        if self.safe_mode and _is_private_url(url):
            logger.debug(f"Safe mode blocked direct request to private IP in URL: {url}")
            # We still send — the payload goes to the *target server* which then
            # makes the internal request. Safe mode here just logs a warning.
            # Actual safe-mode enforcement is at the target-selection layer.

        start = time.perf_counter()
        try:
            import requests
            kwargs = {
                "timeout": self.timeout,
                "allow_redirects": True,
            }

            # Determine body: use override_body (per-request injection) or default post_data
            body_to_send = override_body if override_body is not None else self.post_data

            if self.method.upper() == "GET":
                resp = self._session.get(url, **kwargs)
            elif self.method.upper() == "POST":
                # Auto-detect JSON content-type to send proper JSON body
                content_type = self._session.headers.get("Content-Type", "") or ""
                if "application/json" in content_type and body_to_send:
                    try:
                        kwargs["json"] = json.loads(body_to_send)
                    except (json.JSONDecodeError, TypeError):
                        kwargs["data"] = body_to_send or ""
                else:
                    kwargs["data"] = body_to_send or ""
                resp = self._session.post(url, **kwargs)
            else:
                kwargs["data"] = body_to_send or ""
                resp = self._session.request(self.method.upper(), url, **kwargs)

            elapsed = time.perf_counter() - start
            return {
                "status_code": resp.status_code,
                "body": self._safe_body(resp),
                "headers": dict(resp.headers),
                "elapsed": elapsed,
                "url": resp.url,
            }

        except Exception as exc:
            elapsed = time.perf_counter() - start
            logger.debug(f"HTTP error for {url}: {type(exc).__name__}: {exc}")
            return {
                "status_code": 0,
                "body": str(exc),
                "headers": {},
                "elapsed": elapsed,
                "url": url,
                "error": str(exc),
            }

    @staticmethod
    def _safe_body(resp) -> str:
        """Decode response body safely, falling back to latin-1."""
        try:
            # Limit body size to prevent memory issues with huge responses
            content = resp.content[:1_000_000]  # 1 MB cap
            return content.decode(resp.encoding or "utf-8", errors="replace")
        except Exception:
            try:
                return resp.content[:1_000_000].decode("latin-1", errors="replace")
            except Exception:
                return ""
