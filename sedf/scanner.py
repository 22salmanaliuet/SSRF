"""
sedf/scanner.py - Core SSRF scanning engine

Orchestrates parameter discovery, payload generation, request sending,
and result collection. Implements FR-01 through FR-08.
"""

import time
import uuid
import threading
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from sedf.utils.logger import get_logger
from sedf.utils.http_client import HTTPClient
from sedf.payloads.generator import PayloadGenerator
from sedf.detection.blind import BlindSSRFDetector
from sedf.reporting.reporter import Reporter, Finding, Severity

logger = get_logger(__name__)

COMMON_SSRF_PARAMS = [
    "url", "redirect", "next", "link", "image", "path", "src", "href",
    "dest", "target", "to", "out", "continue", "return", "returnurl",
    "go", "callback", "open", "data", "domain", "host", "website",
    "feed", "site", "page", "view", "service", "endpoint", "proxy",
    "resource", "load", "file", "document", "ref", "uri", "api",
    "img", "photo", "pic", "fetch", "download", "import", "content",
    "request", "remote",
]


class ScanResult:
    """Holds the result of a single payload test."""

    def __init__(
        self,
        url: str,
        param: str,
        payload: str,
        response_code: int,
        response_time: float,
        response_body: str,
        response_headers: dict,
        is_vulnerable: bool = False,
        evidence: str = "",
    ):
        self.url = url
        self.param = param
        self.payload = payload
        self.response_code = response_code
        self.response_time = response_time
        self.response_body = response_body
        self.response_headers = response_headers
        self.is_vulnerable = is_vulnerable
        self.evidence = evidence
        self.timestamp = time.time()
        self.request_id = str(uuid.uuid4())


class Scanner:
    """
    Main SSRF scanning orchestrator.

    Workflow:
        1. Load targets from URL or file
        2. Discover parameters (FR-02)
        3. Generate payloads (FR-03)
        4. Send requests using thread pool (FR-01, NFR-01, NFR-02)
        5. Analyse responses for SSRF indicators (FR-04)
        6. Collect results and pass to reporter (FR-07)
    """

    def __init__(self, args, reporter: Reporter):
        self.args = args
        self.reporter = reporter
        self.client = HTTPClient(args)
        self.payload_gen = PayloadGenerator(args)
        self.blind_detector: Optional[BlindSSRFDetector] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self.found_count = 0

        if args.blind or args.oob_domain:
            self.blind_detector = BlindSSRFDetector(args)

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self):
        """Entry point: load targets and start scan."""
        targets = self._load_targets()
        if not targets:
            logger.error("No valid targets loaded. Exiting.")
            return

        logger.info(f"Loaded {len(targets)} target(s).")

        # Start blind detector callback server if needed
        if self.blind_detector:
            self.blind_detector.start()

        try:
            for target_url in targets:
                logger.info(f"[*] Scanning: {target_url}")
                self._scan_target(target_url)
        finally:
            if self.blind_detector:
                self.blind_detector.stop()

        logger.info(
            f"[✓] Scan complete. {self.found_count} potential vulnerability(ies) found."
        )

    # ── Target Loading ────────────────────────────────────────────────────────

    def _load_targets(self) -> List[str]:
        """Load target URLs from -u argument (URL or file path)."""
        url_arg = self.args.url
        if not url_arg:
            return []

        # Check if it's a file
        try:
            import os
            if os.path.isfile(url_arg):
                with open(url_arg, "r") as fh:
                    lines = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
                logger.info(f"Loaded {len(lines)} URLs from file: {url_arg}")
                return lines
        except Exception:
            pass

        return [url_arg]

    # ── Parameter Discovery ───────────────────────────────────────────────────

    def _discover_parameters(self, url: str) -> List[str]:
        """
        FR-02: Discover potentially vulnerable parameters.

        If FUZZ is already in the URL, we treat whatever parameter holds
        FUZZ as the target. Otherwise we check query params against a
        known-vulnerable list and also try auto-discovery.
        Also handles FUZZ in POST body (--data flag).
        """
        # Check if FUZZ is in POST body data (--data flag)
        post_data = getattr(self.args, "data", None)
        if post_data and "FUZZ" in post_data:
            logger.info("  FUZZ marker found in POST body (--data). Injecting payloads into body.")
            return ["__body__"]

        # If user manually placed FUZZ in URL, extract its parameter name
        if "FUZZ" in url:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            fuzz_params = [k for k, v in params.items() if "FUZZ" in v]
            # Also check path
            if not fuzz_params and "FUZZ" in parsed.path:
                fuzz_params = ["__path__"]
            return fuzz_params or ["FUZZ"]

        # Auto-discovery from query string
        parsed = urlparse(url)
        query_params = list(parse_qs(parsed.query, keep_blank_values=True).keys())

        # Filter to known SSRF-prone parameter names
        if self.args.params:
            user_params = [p.strip() for p in self.args.params.split(",")]
            return user_params

        ssrf_params = [p for p in query_params if p.lower() in COMMON_SSRF_PARAMS]

        if not ssrf_params and query_params:
            # Fall back to testing ALL parameters
            logger.info(
                f"  No known SSRF params found; testing all {len(query_params)} param(s)."
            )
            return query_params

        if not ssrf_params:
            logger.warning(
                "  No query parameters found in URL. "
                "Use FUZZ marker or --params to specify injection point."
            )
            return []

        logger.info(f"  Discovered SSRF candidate params: {ssrf_params}")
        return ssrf_params

    # ── URL Building ──────────────────────────────────────────────────────────

    def _build_url(self, base_url: str, param: str, payload: str) -> str:
        """Inject payload into URL for a given parameter."""
        if "FUZZ" in base_url:
            return base_url.replace("FUZZ", payload, 1)

        parsed = urlparse(base_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if param == "__path__":
            new_path = parsed.path.replace("FUZZ", payload, 1)
            modified = parsed._replace(path=new_path)
            return urlunparse(modified)

        # Replace or add the parameter
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        modified = parsed._replace(query=new_query)
        return urlunparse(modified)

    # ── Scanning ──────────────────────────────────────────────────────────────

    def _scan_target(self, url: str):
        """Scan a single target URL across all parameters and payloads."""
        params = self._discover_parameters(url)
        if not params:
            return

        payloads = self.payload_gen.get_payloads()
        logger.info(
            f"  Testing {len(params)} param(s) × {len(payloads)} payload(s) "
            f"= {len(params) * len(payloads)} request(s)."
        )

        # Build all (param, payload) tasks
        tasks = [(param, payload) for param in params for payload in payloads]

        thread_count = min(self.args.threads, 20)

        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            future_to_task = {
                executor.submit(self._test_single, url, param, payload): (param, payload)
                for param, payload in tasks
            }
            for future in as_completed(future_to_task):
                if self._stop_event.is_set():
                    break
                try:
                    result = future.result()
                    if result:
                        self._handle_result(result)
                except Exception as exc:
                    param, payload = future_to_task[future]
                    logger.debug(f"  Task error [{param}={payload[:30]}]: {exc}")

    def _test_single(self, base_url: str, param: str, payload: str) -> Optional[ScanResult]:
        """Send a single SSRF test request and analyse the response."""
        if self._stop_event.is_set():
            return None

        # Build injected body for POST body injection mode
        injected_body = None
        if param == "__body__":
            post_data_template = getattr(self.args, "data", None) or ""
            injected_body = post_data_template.replace("FUZZ", payload, 1)
            test_url = base_url
        else:
            test_url = self._build_url(base_url, param, payload)

        # Delay between requests
        if self.args.delay > 0:
            time.sleep(self.args.delay)

        # Attach blind-detection UUID if enabled
        oob_token = None
        if self.blind_detector:
            oob_token = str(uuid.uuid4())
            callback_url = self.blind_detector.callback_url_for_token(oob_token)
            
            if injected_body:
                if payload == "http://OOB_CALLBACK_MARKER":
                    injected_body = injected_body.replace("http://OOB_CALLBACK_MARKER", callback_url)
                else:
                    injected_body = injected_body + f"&oob_token={callback_url}"
            else:
                if payload == "http://OOB_CALLBACK_MARKER":
                    test_url = test_url.replace("http://OOB_CALLBACK_MARKER", callback_url)
                else:
                    # Append it as an extra query param to catch generic OOB leaks
                    test_url = test_url + ("&" if "?" in test_url else "?") + f"oob_callback={callback_url}"

        try:
            resp = self.client.get(test_url, override_body=injected_body)
        except Exception as exc:
            logger.debug(f"  Request failed: {exc}")
            return None

        # Analyse response
        is_vulnerable, evidence = self._analyse_response(
            resp, payload, param, oob_token
        )

        result = ScanResult(
            url=test_url,
            param=param,
            payload=payload,
            response_code=resp.get("status_code", 0),
            response_time=resp.get("elapsed", 0.0),
            response_body=resp.get("body", ""),
            response_headers=resp.get("headers", {}),
            is_vulnerable=is_vulnerable,
            evidence=evidence,
        )

        return result

    # ── Response Analysis ─────────────────────────────────────────────────────

    @staticmethod
    def _is_spa_shell(body: str, headers: dict) -> bool:
        """
        Detect Angular/React SPA shell false positives.
        These apps return HTTP 200 with HTML for ALL unknown routes,
        making every request look successful even when the actual
        backend resource doesn't exist.
        """
        content_type = headers.get("Content-Type", headers.get("content-type", ""))
        body_stripped = body.strip().lower()
        is_html_content_type = "text/html" in content_type
        starts_with_doctype = body_stripped.startswith("<!doctype") or body_stripped.startswith("<html")
        # SPA shell heuristic: HTML response that contains no JSON-like data
        has_no_json = "{" not in body[:200]
        return is_html_content_type and starts_with_doctype and has_no_json

    @staticmethod
    def _needs_auth(body: str, status: int) -> bool:
        """Detect if endpoint returned an authentication error."""
        auth_indicators = ["401", "403", "Unauthorized", "Forbidden",
                           "invalid token", "No Authorization", "jwt"]
        if status in (401, 403):
            return True
        body_lower = body.lower()
        return any(a.lower() in body_lower for a in auth_indicators)

    def _analyse_response(
        self,
        resp: dict,
        payload: str,
        param: str,
        oob_token: Optional[str],
    ):
        """
        Heuristic analysis to determine if the response indicates SSRF.

        False Positive Guard:
        - SPA shells (Angular/React) return HTML 200 for all routes → skip
        - Auth-required endpoints return 401/403 → mark as NEEDS AUTH

        Real Findings require:
        - Actual sensitive content in response body (file data, JSON APIs)
        - OOB callback
        - Timing anomalies on non-HTTP schemes
        """
        body = resp.get("body", "")
        status = resp.get("status_code", 0)
        elapsed = resp.get("elapsed", 0.0)
        headers = resp.get("headers", {})

        # ── False Positive Guard ──────────────────────────────────────────────
        # If the response is an SPA HTML shell, skip — it's a false positive.
        # Real SSRF responses will have JSON or binary content, not <!DOCTYPE.
        if self._is_spa_shell(body, headers):
            return False, ""

        # Auth check — not a vulnerability, needs credentials
        if self._needs_auth(body, status):
            logger.debug(f"  Auth required for payload: {payload[:50]}")
            return False, ""

        # 1. Cloud metadata indicators (only valid if NOT SPA shell)
        cloud_indicators = [
            "ami-id", "instance-id", "iam/security-credentials",
            "metadata.google.internal", "169.254.169.254",
            "computeMetadata", "azure-metadata",
        ]
        for indicator in cloud_indicators:
            if indicator.lower() in body.lower():
                return True, f"Cloud metadata indicator found: '{indicator}'"

        # 2. Internal file content indicators
        file_indicators = [
            "root:x:", "[mysql]", "/bin/bash", "daemon:x:", "sys:x:",
            "$6$", "$5$", "$1$"
        ]
        for indicator in file_indicators:
            if indicator in body:
                return True, f"Internal file content indicator: '{indicator}'"

        # 3. localhost/127.0.0.1 in body — ONLY valid if body is JSON or plaintext
        #    (not HTML, to avoid SPA false positives)
        content_type = headers.get("Content-Type", headers.get("content-type", ""))
        is_json_response = "application/json" in content_type
        is_plain_text    = "text/plain" in content_type
        if (is_json_response or is_plain_text) and any(
            ind in body for ind in ["localhost", "127.0.0.1"]
        ):
            return True, f"Internal address found in {'JSON' if is_json_response else 'text'} response"

        # 4. Redis/internal service indicators
        service_indicators = [
            "+PONG", "+OK", "redis_version", "INFO server",
            "220 FTP", "SSH-2.0",
        ]
        for indicator in service_indicators:
            if indicator in body:
                return True, f"Internal service response detected: '{indicator}'"

        # 5. OOB callback check (blind SSRF - FR-04)
        if oob_token and self.blind_detector:
            if self.blind_detector.check_callback(oob_token):
                return True, f"OOB callback received for token: {oob_token}"

        # 6. JSON response on internal IP payloads → real API data leaked
        if is_json_response and status == 200 and any(
            internal in payload for internal in ["127.0.0.1", "localhost", "169.254"]
        ):
            return True, f"JSON API response on internal IP payload (status: {status})"

        # 7. Status code anomaly: 200 on internal payloads — ONLY if non-HTML
        body_stripped = body.strip().lower()
        is_html = body_stripped.startswith("<!doctype") or body_stripped.startswith("<html")
        if status == 200 and not is_html and any(
            internal in payload for internal in ["127.0.0.1", "localhost", "169.254"]
        ):
            return True, f"HTTP 200 on internal IP payload (status: {status})"

        # 6. Timing anomaly (time-based blind SSRF fallback)
        if elapsed > 5.0 and any(
            scheme in payload for scheme in ["gopher://", "dict://", "ftp://"]
        ):
            return True, f"Response time anomaly ({elapsed:.1f}s) on non-HTTP scheme"

        # 7. SSRF error messages that reveal internal interaction
        error_indicators = [
            "Connection refused", "No route to host", "Name or service not known",
            "ECONNREFUSED", "connection refused", "getaddrinfo",
        ]
        for indicator in error_indicators:
            if indicator in body:
                return True, f"Internal connection error exposed: '{indicator}'"

        return False, ""

    # ── Result Handling ───────────────────────────────────────────────────────

    def _handle_result(self, result: ScanResult):
        """Log and report a finding."""
        with self._lock:
            if result.is_vulnerable:
                self.found_count += 1
                severity = self._determine_severity(result.payload, result.evidence)
                finding = Finding(
                    url=result.url,
                    param=result.param,
                    payload=result.payload,
                    evidence=result.evidence,
                    severity=severity,
                    response_code=result.response_code,
                    response_time=result.response_time,
                    timestamp=result.timestamp,
                )
                self.reporter.add_finding(finding)

                red    = "\033[31m"
                green  = "\033[32m"
                yellow = "\033[33m"
                cyan   = "\033[36m"
                reset  = "\033[0m"
                bold   = "\033[1m"

                print(
                    f"\n  {red}{bold}[VULN] SSRF detected!{reset}\n"
                    f"         URL   : {result.url}\n"
                    f"         Param : {result.param}\n"
                    f"         Payload: {result.payload}\n"
                    f"         Evidence: {result.evidence}\n"
                    f"         Severity: {severity.value}\n"
                )

                # --extract mode: display the actual server response content
                if getattr(self.args, 'extract', False) and result.response_body:
                    body_preview = result.response_body.strip()[:2000]
                    print(f"  {cyan}{bold}  ╔══ EXTRACTED RESPONSE CONTENT ══════════════════════════{reset}")
                    print(f"  {cyan}  ║  Payload : {yellow}{result.payload}{reset}")
                    print(f"  {cyan}  ║  HTTP    : {result.response_code}  |  Time: {result.response_time:.2f}s{reset}")
                    print(f"  {cyan}  ╠══ DATA ═════════════════════════════════════════════════{reset}")
                    for line in body_preview.splitlines():
                        print(f"  {cyan}  ║{reset}  {green}{line}{reset}")
                    print(f"  {cyan}  ╚══════════════════════════════════════════════════════════{reset}\n")

            else:
                msg = (
                    f"  [-] {result.param}='{result.payload}' "
                    f"=> {result.response_code} ({result.response_time:.2f}s)"
                )
                logger.info(msg)
                if hasattr(self.reporter, 'log'):
                    self.reporter.log(msg)

    def _determine_severity(self, payload: str, evidence: str) -> Severity:
        """Map payload type and evidence to a severity rating."""
        if "Cloud metadata" in evidence or "Internal file content" in evidence:
            return Severity.CRITICAL
        if "Internal service" in evidence or "OOB callback" in evidence:
            return Severity.HIGH
        if "200" in evidence and "internal" in evidence.lower():
            return Severity.MEDIUM
        if "time anomaly" in evidence or "error exposed" in evidence:
            return Severity.LOW
        return Severity.INFO
