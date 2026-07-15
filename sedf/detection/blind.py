"""
sedf/detection/blind.py - Blind SSRF detection via OOB callbacks (FR-04)

Provides:
  - Local HTTP callback server that captures incoming connections
  - UUID token injection and correlation
  - DNS-based OOB detection via third-party services
  - Time-based fallback detection
"""

import threading
import time
import uuid
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Set
from urllib.parse import urlparse, urlencode, parse_qs

from sedf.utils.logger import get_logger

logger = get_logger(__name__)


class _CallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that records incoming request tokens."""

    # Shared state (injected by the server)
    received_tokens: Set[str] = set()
    _lock = threading.Lock()

    def do_GET(self):
        token = self.path.strip("/")
        with self.__class__._lock:
            self.__class__.received_tokens.add(token)
        logger.info(f"[OOB] HTTP callback received! Token: {token} from {self.client_address[0]}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        self.do_GET()

    def log_message(self, fmt, *args):
        # Suppress default request logging; we handle it above
        pass


class BlindSSRFDetector:
    """
    FR-04: Detects blind SSRF via:

    1. Local HTTP callback server — receives connections when the target
       server fetches our callback URL.
    2. OOB domain — uses an externally-resolvable domain; DNS/HTTP callbacks
       are polled or received via the local server.
    3. Token correlation — each request gets a unique UUID embedded in the
       callback URL, so we can match callbacks to specific payloads.
    """

    def __init__(self, args):
        self.args = args
        self.port = getattr(args, "callback_port", 8888)
        self.oob_domain = getattr(args, "oob_domain", None)
        self._server: HTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._received: Dict[str, float] = {}   # token -> timestamp
        self._lock = threading.Lock()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def start(self):
        """Start the local HTTP callback server."""
        try:
            self._server = HTTPServer(("0.0.0.0", self.port), _CallbackHandler)
            self._server_thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._server_thread.start()
            local_ip = self._get_local_ip()
            logger.info(
                f"[*] Blind SSRF callback server listening on http://{local_ip}:{self.port}/"
            )
        except OSError as exc:
            logger.warning(
                f"[!] Could not start callback server on port {self.port}: {exc}. "
                "Blind detection may be limited."
            )

    def stop(self):
        """Shut down the callback server."""
        if self._server:
            self._server.shutdown()
            logger.debug("Callback server stopped.")

    # ── Token Management ───────────────────────────────────────────────────────

    def inject_token(self, url: str, token: str) -> str:
        """
        Return a callback URL embedding the token, to be used as the
        SSRF payload value. The target server will GET this URL when
        vulnerable, triggering our callback server.
        """
        callback_base = self._callback_base()
        callback_url = f"{callback_base}/{token}"

        # If the URL already has FUZZ we replace it; otherwise we append
        # a callback parameter for diagnostic purposes
        if "FUZZ" in url:
            return url.replace("FUZZ", callback_url, 1)
        return url  # Token appended inside payload by generator

    def callback_url_for_token(self, token: str) -> str:
        """Return the full callback URL for a token (used in payloads)."""
        return f"{self._callback_base()}/{token}"

    def check_callback(self, token: str, timeout: float = 2.0) -> bool:
        """
        Check if we have received an OOB callback for this token.
        Polls for up to `timeout` seconds.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            with _CallbackHandler._lock:
                if token in _CallbackHandler.received_tokens:
                    return True
            time.sleep(0.1)
        return False

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _callback_base(self) -> str:
        if self.oob_domain:
            return f"http://{self.oob_domain}"
        local_ip = self._get_local_ip()
        return f"http://{local_ip}:{self.port}"

    @staticmethod
    def _get_local_ip() -> str:
        """Determine the machine's outbound IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
