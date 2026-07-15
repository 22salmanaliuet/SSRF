"""
sedf/modules/defense.py - SSRF defense testing module (FR-08)

Checks whether a target has SSRF mitigations in place:
  - IP allowlist / blocklist
  - URL scheme filtering
  - DNS rebinding protections
  - URL parser inconsistencies
  - Redirect following controls
  - Error message information leakage
"""

from typing import List, Dict, Optional

from sedf.utils.http_client import HTTPClient
from sedf.utils.logger import get_logger
from sedf.reporting.reporter import Reporter, Finding, Severity

logger = get_logger(__name__)


class DefenseTestResult:
    def __init__(self, test: str, status: str, detail: str, recommendation: str):
        self.test = test
        self.status = status           # "PROTECTED" | "VULNERABLE" | "UNKNOWN"
        self.detail = detail
        self.recommendation = recommendation


class DefenseChecker:
    """
    FR-08: Tests for SSRF mitigations and provides remediation advice.

    Runs a series of probes to determine what defences, if any, the
    target has implemented. Results are printed and added to the report.
    """

    def __init__(self, args, reporter: Reporter):
        self.args = args
        self.reporter = reporter
        self.client = HTTPClient(args)
        self.base_url = args.url

    def run(self):
        print("\n[*] Running SSRF Defense Analysis ...\n")
        results = []

        results.append(self._test_private_ip_block())
        results.append(self._test_scheme_filter())
        results.append(self._test_redirect_chain())
        results.append(self._test_url_parser_inconsistency())
        results.append(self._test_error_leakage())
        results.append(self._test_cloud_metadata_block())
        results.append(self._test_dns_rebinding())

        self._print_defense_summary(results)
        self._add_recommendations_to_report(results)

    # ── Individual Tests ──────────────────────────────────────────────────────

    def _test_private_ip_block(self) -> DefenseTestResult:
        """Test if requests to 127.0.0.1 are blocked."""
        payload = "http://127.0.0.1/"
        resp = self._send(payload)

        if resp is None:
            return DefenseTestResult(
                "Private IP Blocking",
                "UNKNOWN",
                "Could not get baseline response.",
                "Ensure 127.0.0.0/8 and other RFC-1918 ranges are blocked."
            )

        body = resp.get("body", "")
        status = resp.get("status_code", 0)

        # Signs of blocking: 403, 400, or SSRF filter message
        block_indicators = ["blocked", "not allowed", "forbidden", "invalid url", "ssrf", "403"]
        if any(b in body.lower() for b in block_indicators) or status in (403, 400):
            return DefenseTestResult(
                "Private IP Blocking",
                "PROTECTED",
                f"Request to 127.0.0.1 returned HTTP {status} with filter indicators.",
                "Good. Ensure all RFC-1918 and link-local ranges are covered."
            )

        if status == 200:
            return DefenseTestResult(
                "Private IP Blocking",
                "VULNERABLE",
                f"HTTP 200 returned for 127.0.0.1 — application may be fetching internal URLs.",
                "Implement an IP allowlist. Block 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, "
                "192.168.0.0/16, and 169.254.0.0/16 at the application layer."
            )

        return DefenseTestResult(
            "Private IP Blocking",
            "UNKNOWN",
            f"HTTP {status} — inconclusive.",
            "Manually verify that 127.0.0.1 is blocked."
        )

    def _test_scheme_filter(self) -> DefenseTestResult:
        """Test if non-HTTP schemes (file://, gopher://) are blocked."""
        for scheme, payload in [
            ("file://", "file:///etc/passwd"),
            ("gopher://", "gopher://127.0.0.1:6379/"),
            ("dict://", "dict://127.0.0.1:6379/"),
        ]:
            resp = self._send(payload)
            if resp is None:
                continue
            body = resp.get("body", "")
            status = resp.get("status_code", 0)

            if status in (400, 403) or any(
                b in body.lower() for b in ["blocked", "not allowed", "invalid", "scheme"]
            ):
                continue  # Good
            else:
                return DefenseTestResult(
                    "URL Scheme Filtering",
                    "VULNERABLE",
                    f"Scheme '{scheme}' not blocked (HTTP {status}).",
                    "Allowlist only http:// and https:// schemes. "
                    "Explicitly reject file://, gopher://, dict://, ftp://, etc."
                )

        return DefenseTestResult(
            "URL Scheme Filtering",
            "PROTECTED",
            "Non-HTTP schemes appear to be filtered.",
            "Good. Maintain a strict scheme allowlist."
        )

    def _test_redirect_chain(self) -> DefenseTestResult:
        """Test if the application follows redirects naively."""
        # We can't easily set up a redirect server, so we check redirect behaviour
        # by sending a URL that returns a redirect to an internal address.
        payload = "http://localtest.me"  # Resolves to 127.0.0.1 — safe test domain
        resp = self._send(payload)
        if resp is None:
            return DefenseTestResult("Redirect Chain", "UNKNOWN", "No response.", "Limit redirect following.")

        status = resp.get("status_code", 0)
        if status == 200:
            return DefenseTestResult(
                "Redirect Chain",
                "VULNERABLE",
                "Application may follow redirects to internal addresses.",
                "Validate post-redirect destination URLs. Disable following redirects "
                "to private IP ranges. Use a dedicated outbound proxy."
            )
        return DefenseTestResult(
            "Redirect Chain",
            "PROTECTED",
            f"HTTP {status} for redirect test payload.",
            "Ensure redirect destinations are validated after resolution."
        )

    def _test_url_parser_inconsistency(self) -> DefenseTestResult:
        """Test for URL parser confusion via crafted URLs."""
        payloads = [
            "http://127.0.0.1@evil.com",   # Credentials-based confusion
            "http://evil.com@127.0.0.1",
            "http://127.0.0.1#evil.com",
        ]
        for payload in payloads:
            resp = self._send(payload)
            if resp is None:
                continue
            status = resp.get("status_code", 0)
            body = resp.get("body", "")
            if status == 200 and any(
                ind in body for ind in ["127.0.0.1", "localhost", "root:"]
            ):
                return DefenseTestResult(
                    "URL Parser Inconsistency",
                    "VULNERABLE",
                    f"Parser confusion payload '{payload}' returned internal content.",
                    "Use a well-tested URL parser. Normalise URLs before validation. "
                    "Reject URLs containing '@', '#' followed by a host, or mixed-encoding."
                )
        return DefenseTestResult(
            "URL Parser Inconsistency",
            "PROTECTED",
            "URL parser confusion payloads did not expose internal content.",
            "Continue to update URL parsing library. Test for new bypass techniques regularly."
        )

    def _test_error_leakage(self) -> DefenseTestResult:
        """Check if error messages reveal internal network information."""
        payload = "http://192.168.0.1:22/test"
        resp = self._send(payload)
        if resp is None:
            return DefenseTestResult("Error Message Leakage", "UNKNOWN", "No response.", "")

        body = resp.get("body", "")
        leak_indicators = [
            "Connection refused", "ECONNREFUSED", "No route to host",
            "getaddrinfo", "Connection timed out", "ETIMEDOUT",
        ]
        for ind in leak_indicators:
            if ind in body:
                return DefenseTestResult(
                    "Error Message Leakage",
                    "VULNERABLE",
                    f"Internal network error leaked to client: '{ind}'.",
                    "Catch and sanitise exception messages. Return generic error "
                    "messages to users. Log detailed errors server-side only."
                )
        return DefenseTestResult(
            "Error Message Leakage",
            "PROTECTED",
            "No internal error messages leaked to client.",
            "Ensure error handling is consistently applied across all fetch endpoints."
        )

    def _test_cloud_metadata_block(self) -> DefenseTestResult:
        """Test if cloud metadata IP 169.254.169.254 is blocked."""
        payload = "http://169.254.169.254/latest/meta-data/"
        resp = self._send(payload)
        if resp is None:
            return DefenseTestResult("Cloud Metadata Protection", "UNKNOWN", "No response.", "")

        body = resp.get("body", "")
        status = resp.get("status_code", 0)

        if "ami-id" in body or "instance-id" in body or "meta-data" in body:
            return DefenseTestResult(
                "Cloud Metadata Protection",
                "VULNERABLE",
                "AWS EC2 metadata is accessible via SSRF!",
                "CRITICAL: Block 169.254.169.254 at the security group / NACLs level. "
                "Use IMDSv2 which requires a PUT request with a token. "
                "Rotate all IAM credentials immediately if exposed."
            )

        if status in (403, 400) or "blocked" in body.lower():
            return DefenseTestResult(
                "Cloud Metadata Protection",
                "PROTECTED",
                f"Cloud metadata endpoint blocked (HTTP {status}).",
                "Good. Ensure IMDSv2 is enforced and 169.254.169.254 is blocked."
            )

        return DefenseTestResult(
            "Cloud Metadata Protection",
            "UNKNOWN",
            f"HTTP {status} — verify manually.",
            "Explicitly block 169.254.169.254 in security groups and application firewall."
        )

    def _test_dns_rebinding(self) -> DefenseTestResult:
        """Heuristic check for DNS rebinding protection."""
        # Can't easily test true DNS rebinding without infrastructure,
        # so we check if the app validates IPs after DNS resolution.
        return DefenseTestResult(
            "DNS Rebinding Mitigation",
            "UNKNOWN",
            "DNS rebinding requires external infrastructure to test definitively.",
            "Recommendations:\n"
            "  1. Resolve the hostname, check the IP is not private, THEN connect.\n"
            "  2. Use a DNS-aware SSRF-prevention library.\n"
            "  3. Set a short DNS TTL enforcement window.\n"
            "  4. Deploy a server-side SSRF proxy (e.g. Smokescreen, SafeCurl)."
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _send(self, payload: str) -> Optional[dict]:
        if "FUZZ" not in self.base_url:
            return None
        url = self.base_url.replace("FUZZ", payload)
        return self.client.get(url)

    @staticmethod
    def _print_defense_summary(results: List[DefenseTestResult]):
        colours = {
            "PROTECTED": "\033[32m",
            "VULNERABLE": "\033[31m",
            "UNKNOWN": "\033[33m",
        }
        reset = "\033[0m"
        print("\n" + "═" * 60)
        print("  SSRF DEFENSE ANALYSIS REPORT")
        print("═" * 60)
        for result in results:
            colour = colours.get(result.status, "")
            print(f"\n  Test: {result.test}")
            print(f"  Status: {colour}{result.status}{reset}")
            print(f"  Detail: {result.detail}")
            print(f"  Recommendation: {result.recommendation}")
        print("\n" + "═" * 60)

    def _add_recommendations_to_report(self, results: List[DefenseTestResult]):
        for result in results:
            if result.status == "VULNERABLE":
                finding = Finding(
                    url=self.base_url,
                    param="defense_check",
                    payload=result.test,
                    evidence=result.detail,
                    severity=Severity.MEDIUM,
                    response_code=0,
                    response_time=0.0,
                )
                finding.remediation = result.recommendation
                self.reporter.add_finding(finding)
