"""
tests/ - SEDF unit and integration tests
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch

# Ensure package is importable from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sedf.payloads.generator import PayloadGenerator, PAYLOAD_SETS
from sedf.reporting.reporter import Reporter, Finding, Severity
from sedf.scanner import Scanner, COMMON_SSRF_PARAMS


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_args(**kwargs):
    """Create a minimal args namespace."""
    defaults = dict(
        url="http://test.local/?url=FUZZ",
        payloads="default",
        payload_file=None,
        params=None,
        blind=False,
        oob_domain=None,
        callback_port=8888,
        exploit=False,
        module=None,
        ports="22,80,443",
        internal_ip="127.0.0.1",
        defense=False,
        threads=5,
        timeout=5,
        delay=0.0,
        proxy=None,
        headers=None,
        method="GET",
        data=None,
        cookies=None,
        output=None,
        format="terminal",
        verbose=False,
        quiet=True,
        safe_mode=True,
        no_safe_mode=False,
        confirm=True,
        lab=False,
    )
    defaults.update(kwargs)
    ns = types.SimpleNamespace(**defaults)
    return ns


# ── Payload Generator Tests ────────────────────────────────────────────────────

class TestPayloadGenerator(unittest.TestCase):

    def test_default_payloads_not_empty(self):
        args = _make_args(payloads="default")
        gen = PayloadGenerator(args)
        payloads = gen.get_payloads()
        self.assertGreater(len(payloads), 0)

    def test_all_payloads_superset(self):
        args_all = _make_args(payloads="all")
        args_default = _make_args(payloads="default")
        all_p = PayloadGenerator(args_all).get_payloads()
        default_p = PayloadGenerator(args_default).get_payloads()
        self.assertGreater(len(all_p), len(default_p))

    def test_http_payloads_contain_localhost(self):
        payloads = PAYLOAD_SETS["http"]
        has_localhost = any("127.0.0.1" in p or "localhost" in p for p in payloads)
        self.assertTrue(has_localhost)

    def test_cloud_payloads_contain_aws(self):
        payloads = PAYLOAD_SETS["cloud"]
        has_aws = any("169.254.169.254" in p for p in payloads)
        self.assertTrue(has_aws)

    def test_custom_file_not_found(self):
        args = _make_args(payload_file="/nonexistent/path.txt", payloads="default")
        gen = PayloadGenerator(args)
        # Should fall back to built-in
        payloads = gen.get_payloads()
        self.assertGreater(len(payloads), 0)

    def test_port_scan_payloads(self):
        payloads = PayloadGenerator.get_port_scan_payloads("127.0.0.1", [80, 443, 6379])
        self.assertEqual(len(payloads), 12)  # 3 ports × 4 schemes

    def test_redis_payloads(self):
        payloads = PayloadGenerator.get_redis_payloads()
        self.assertTrue(all("gopher://" in p for p in payloads))

    def test_gcp_cloud_payloads(self):
        payloads = PayloadGenerator.get_cloud_payloads("gcp")
        self.assertTrue(any("google" in p or "computeMetadata" in p for p in payloads))


# ── Reporter Tests ─────────────────────────────────────────────────────────────

class TestReporter(unittest.TestCase):

    def _make_reporter(self):
        args = _make_args(output=None, format="terminal")
        return Reporter(args)

    def test_add_finding_populates_list(self):
        reporter = self._make_reporter()
        finding = Finding(
            url="http://test.local/?url=http://127.0.0.1",
            param="url",
            payload="http://127.0.0.1",
            evidence="HTTP 200 on internal IP",
            severity=Severity.HIGH,
            response_code=200,
            response_time=0.5,
        )
        reporter.add_finding(finding)
        self.assertEqual(len(reporter.findings), 1)

    def test_finding_gets_remediation(self):
        reporter = self._make_reporter()
        finding = Finding(
            url="http://test.local/?url=FUZZ",
            param="url",
            payload="http://169.254.169.254/",
            evidence="Cloud metadata indicator found",
            severity=Severity.CRITICAL,
            response_code=200,
            response_time=0.1,
        )
        reporter.add_finding(finding)
        self.assertNotEqual(reporter.findings[0].remediation, "")

    def test_severity_enum_values(self):
        for sev in Severity:
            self.assertIsInstance(sev.value, str)

    def test_to_dict_includes_iso_timestamp(self):
        finding = Finding(
            url="http://test/",
            param="url",
            payload="test",
            evidence="test",
            severity=Severity.INFO,
            response_code=200,
            response_time=0.1,
        )
        d = finding.to_dict()
        self.assertIn("timestamp_iso", d)
        self.assertIn("T", d["timestamp_iso"])


# ── Scanner Tests ──────────────────────────────────────────────────────────────

class TestScanner(unittest.TestCase):

    def _make_scanner(self, **kwargs):
        args = _make_args(**kwargs)
        reporter = Reporter(args)
        return Scanner(args, reporter), reporter

    def test_discover_fuzz_param(self):
        scanner, _ = self._make_scanner(url="http://test.local/?url=FUZZ")
        params = scanner._discover_parameters("http://test.local/?url=FUZZ")
        self.assertIn("url", params)

    def test_discover_known_params(self):
        scanner, _ = self._make_scanner()
        params = scanner._discover_parameters("http://test.local/?redirect=http://x.com&other=1")
        self.assertIn("redirect", params)

    def test_build_url_replaces_fuzz(self):
        scanner, _ = self._make_scanner()
        result = scanner._build_url(
            "http://test.local/?url=FUZZ", "url", "http://127.0.0.1"
        )
        self.assertEqual(result, "http://test.local/?url=http://127.0.0.1")

    def test_build_url_injects_param(self):
        scanner, _ = self._make_scanner()
        result = scanner._build_url(
            "http://test.local/?url=original", "url", "http://127.0.0.1"
        )
        self.assertIn("http%3A%2F%2F127.0.0.1", result)

    def test_analyse_cloud_metadata(self):
        scanner, _ = self._make_scanner()
        resp = {"body": "ami-id\nhostname\niam/", "status_code": 200, "elapsed": 0.1, "headers": {}}
        is_vuln, evidence = scanner._analyse_response(resp, "http://169.254.169.254/", "url", None)
        self.assertTrue(is_vuln)
        self.assertIn("metadata", evidence.lower())

    def test_analyse_redis_banner(self):
        scanner, _ = self._make_scanner()
        resp = {"body": "+PONG\r\n", "status_code": 200, "elapsed": 0.05, "headers": {}}
        is_vuln, evidence = scanner._analyse_response(resp, "gopher://127.0.0.1:6379/", "url", None)
        self.assertTrue(is_vuln)

    def test_analyse_file_content(self):
        scanner, _ = self._make_scanner()
        resp = {"body": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", "status_code": 200, "elapsed": 0.1, "headers": {}}
        is_vuln, evidence = scanner._analyse_response(resp, "file:///etc/passwd", "url", None)
        self.assertTrue(is_vuln)

    def test_analyse_clean_response(self):
        scanner, _ = self._make_scanner()
        resp = {"body": "<html><body>Hello World</body></html>", "status_code": 200, "elapsed": 0.1, "headers": {}}
        is_vuln, _ = scanner._analyse_response(resp, "http://example.com", "url", None)
        self.assertFalse(is_vuln)

    def test_common_ssrf_params_list(self):
        self.assertIn("url", COMMON_SSRF_PARAMS)
        self.assertIn("redirect", COMMON_SSRF_PARAMS)
        self.assertIn("next", COMMON_SSRF_PARAMS)

    def test_severity_critical_for_cloud(self):
        scanner, _ = self._make_scanner()
        sev = scanner._determine_severity("http://169.254.169.254/", "Cloud metadata indicator found: 'ami-id'")
        self.assertEqual(sev, Severity.CRITICAL)

    def test_load_targets_url(self):
        scanner, _ = self._make_scanner(url="http://example.com/?url=FUZZ")
        targets = scanner._load_targets()
        self.assertEqual(targets, ["http://example.com/?url=FUZZ"])


# ── Integration-like Tests (with mocked HTTP) ─────────────────────────────────

class TestScannerIntegration(unittest.TestCase):

    @patch("sedf.utils.http_client.HTTPClient.get")
    def test_single_request_finds_vuln(self, mock_get):
        mock_get.return_value = {
            "status_code": 200,
            "body": "root:x:0:0:root:/root:/bin/bash",
            "headers": {},
            "elapsed": 0.1,
        }
        args = _make_args(
            url="http://test.local/?url=FUZZ",
            payloads="file",
            threads=1,
            confirm=True,
            quiet=True,
        )
        reporter = Reporter(args)
        scanner = Scanner(args, reporter)
        scanner._scan_target("http://test.local/?url=FUZZ")
        self.assertGreater(scanner.found_count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
