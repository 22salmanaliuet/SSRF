"""
sedf/modules/port_scanner.py - Internal port scanning via SSRF (FR-05)

Probes internal services by injecting port-specific URLs as SSRF payloads
and interpreting response timing and status to infer port state.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from sedf.utils.http_client import HTTPClient
from sedf.utils.logger import get_logger

logger = get_logger(__name__)

# Default ports to probe — covers common internal services
DEFAULT_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    80,    # HTTP
    443,   # HTTPS
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    8080,  # HTTP alternate
    8443,  # HTTPS alternate
    9200,  # Elasticsearch
    11211, # Memcached
    27017, # MongoDB
]

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    80: "HTTP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}


class PortScanResult:
    def __init__(self, port: int, state: str, service: str, evidence: str, response_time: float):
        self.port = port
        self.state = state          # "open" | "closed" | "filtered"
        self.service = service
        self.evidence = evidence
        self.response_time = response_time


class SSRFPortScanner:
    """
    FR-05: Probes internal ports via SSRF.

    Technique:
      - Injects http://<internal_ip>:<port>/ as the SSRF payload
      - Open ports: fast HTTP 200 or service banner in body
      - Closed ports: connection refused error, fast response
      - Filtered ports: timeout / very slow response
    """

    OPEN_TIMEOUT_THRESHOLD = 3.0    # seconds — if slower, likely filtered
    CLOSED_FAST_THRESHOLD = 0.5     # seconds — if very fast + error, likely closed

    def __init__(self, args, client: HTTPClient):
        self.args = args
        self.client = client
        self.internal_ip = getattr(args, "internal_ip", "127.0.0.1")

    def scan(self, ports: List[int] = None, base_url_template: str = None) -> List[PortScanResult]:
        """
        Scan the given ports on the internal IP via SSRF.

        base_url_template: The target URL with FUZZ in place of the payload,
            e.g. "http://victim.com/fetch?url=FUZZ"
        """
        if ports is None:
            raw = getattr(self.args, "ports", "")
            if raw:
                ports = [int(p.strip()) for p in raw.split(",") if p.strip().isdigit()]
            else:
                ports = DEFAULT_PORTS

        results: List[PortScanResult] = []
        thread_count = min(getattr(self.args, "threads", 5), 20)

        logger.info(f"[PORT SCAN] Probing {len(ports)} ports on {self.internal_ip} via SSRF ...")

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            future_to_port = {
                executor.submit(
                    self._probe_port, port, base_url_template
                ): port
                for port in ports
            }
            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        self._print_result(result)
                except Exception as exc:
                    port = future_to_port[future]
                    logger.debug(f"Port {port} probe error: {exc}")

        results.sort(key=lambda r: r.port)
        self._print_summary(results)
        return results

    def _probe_port(self, port: int, base_url_template: str = None) -> PortScanResult:
        service = PORT_SERVICE_MAP.get(port, "unknown")
        payload = f"http://{self.internal_ip}:{port}/"

        if base_url_template and "FUZZ" in base_url_template:
            url = base_url_template.replace("FUZZ", payload)
        else:
            url = payload

        resp = self.client.get(url)
        elapsed = resp.get("elapsed", 0.0)
        body = resp.get("body", "")
        status = resp.get("status_code", 0)

        state, evidence = self._classify(status, elapsed, body, port)
        return PortScanResult(port, state, service, evidence, elapsed)

    def _classify(
        self, status: int, elapsed: float, body: str, port: int
    ):
        """Determine port state from response characteristics."""

        # Explicit connection-refused errors → closed
        refused_indicators = [
            "Connection refused", "ECONNREFUSED", "connection refused",
            "No connection could be made", "actively refused",
        ]
        for ind in refused_indicators:
            if ind in body:
                return "closed", f"Connection refused ({elapsed:.2f}s)"

        # Timeout / very slow → filtered or stealthy
        if elapsed >= self.OPEN_TIMEOUT_THRESHOLD:
            return "filtered", f"Timeout ({elapsed:.2f}s) — port may be filtered"

        # HTTP 200 or service banners → open
        if status == 200:
            return "open", f"HTTP {status} received in {elapsed:.2f}s"

        # Service banners in body
        banner_indicators = {
            "+PONG": "Redis PONG",
            "+OK": "Redis OK",
            "SSH-": "SSH banner",
            "220 FTP": "FTP banner",
            "220 ESMTP": "SMTP banner",
            "HTTP/1.": "HTTP response",
        }
        for indicator, label in banner_indicators.items():
            if indicator in body:
                return "open", f"{label} received ({elapsed:.2f}s)"

        # Non-zero status and fast → likely open but returning error
        if status > 0 and elapsed < self.OPEN_TIMEOUT_THRESHOLD:
            return "open", f"HTTP {status} in {elapsed:.2f}s (port is reachable)"

        return "unknown", f"Inconclusive ({status}, {elapsed:.2f}s)"

    @staticmethod
    def _print_result(result: PortScanResult):
        colours = {"open": "\033[32m", "closed": "\033[31m", "filtered": "\033[33m"}
        colour = colours.get(result.state, "\033[37m")
        reset = "\033[0m"
        print(
            f"  {colour}[{result.state.upper():<8}]{reset} "
            f"Port {result.port:<6} {result.service:<15} {result.evidence}"
        )

    @staticmethod
    def _print_summary(results: List[PortScanResult]):
        open_ports = [r for r in results if r.state == "open"]
        print(f"\n  Port scan complete. {len(open_ports)}/{len(results)} port(s) open.")
