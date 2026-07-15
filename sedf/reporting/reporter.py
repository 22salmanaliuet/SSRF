"""
sedf/reporting/reporter.py - Reporting and logging module (FR-07)

Collects findings during a scan and outputs them in:
  - Terminal (coloured, human-readable summary)
  - JSON
  - CSV
"""

import json
import csv
import time
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional

from sedf.utils.logger import get_logger

logger = get_logger(__name__)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


_SEVERITY_COLOURS = {
    Severity.CRITICAL: "\033[1;35m",   # Bold magenta
    Severity.HIGH:     "\033[1;31m",   # Bold red
    Severity.MEDIUM:   "\033[33m",     # Yellow
    Severity.LOW:      "\033[36m",     # Cyan
    Severity.INFO:     "\033[37m",     # White
}
_RESET = "\033[0m"


@dataclass
class Finding:
    url: str
    param: str
    payload: str
    evidence: str
    severity: Severity
    response_code: int
    response_time: float
    timestamp: float = field(default_factory=time.time)
    remediation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["timestamp_iso"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)
        )
        return d


REMEDIATIONS = {
    Severity.CRITICAL: (
        "IMMEDIATE ACTION REQUIRED. An attacker can access cloud metadata or internal files. "
        "Implement a strict URL allowlist, disable SSRF-vulnerable parameters, and rotate "
        "any exposed credentials immediately."
    ),
    Severity.HIGH: (
        "Block internal IP ranges (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, "
        "192.168.0.0/16) at the application layer. Use a DNS rebinding-resistant resolver. "
        "Consider disabling gopher:// and other non-HTTP schemes."
    ),
    Severity.MEDIUM: (
        "Validate and sanitize URL inputs server-side. Implement an allowlist of permitted "
        "domains/IPs. Use a dedicated outbound proxy that enforces these rules."
    ),
    Severity.LOW: (
        "Review URL fetching logic. Ensure error messages do not reveal internal network "
        "topology. Apply defence-in-depth measures."
    ),
    Severity.INFO: (
        "Informational finding. Review manually to confirm exploitability."
    ),
}


class Reporter:
    """
    Collects findings and writes reports (FR-07).
    Supports terminal, JSON, and CSV output formats.
    """

    def __init__(self, args):
        self.args = args
        self.findings: List[Finding] = []
        self.scan_start = time.time()
        self._output_file = getattr(args, "output", None)
        self._fmt = getattr(args, "format", "terminal")

    def add_finding(self, finding: Finding):
        """Add a remediation hint and store the finding."""
        finding.remediation = REMEDIATIONS.get(finding.severity, "")
        self.findings.append(finding)

    def finalize(self):
        """Write the final report after the scan completes."""
        elapsed = time.time() - self.scan_start
        self._print_terminal_summary(elapsed)

        if self._output_file or self._fmt in ("json", "csv", "all"):
            self._write_files(elapsed)

    # ── Terminal Summary ──────────────────────────────────────────────────────

    def _print_terminal_summary(self, elapsed: float):
        print("\n" + "═" * 60)
        print("  SEDF SCAN REPORT")
        print("═" * 60)
        print(f"  Scan Duration : {elapsed:.1f}s")
        print(f"  Total Findings: {len(self.findings)}")

        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            c = counts.get(sev, 0)
            if c:
                colour = _SEVERITY_COLOURS[sev]
                print(f"  {colour}{sev.value:<10}{_RESET}: {c}")

        print("═" * 60)

        if not self.findings:
            print("  No SSRF vulnerabilities detected.")
            print("  (This does not guarantee the target is safe — try --payloads all)")
        else:
            for i, finding in enumerate(self.findings, 1):
                colour = _SEVERITY_COLOURS[finding.severity]
                print(f"\n  Finding #{i}")
                print(f"  {'─'*55}")
                print(f"  Severity  : {colour}{finding.severity.value}{_RESET}")
                print(f"  URL       : {finding.url}")
                print(f"  Parameter : {finding.param}")
                print(f"  Payload   : {finding.payload}")
                print(f"  Evidence  : {finding.evidence}")
                print(f"  HTTP Code : {finding.response_code}")
                print(f"  Resp Time : {finding.response_time:.2f}s")
                print(f"  Remediation:")
                for line in finding.remediation.split(". "):
                    if line.strip():
                        print(f"    • {line.strip()}.")

        print("\n" + "═" * 60)

    # ── File Output ───────────────────────────────────────────────────────────

    def _write_files(self, elapsed: float):
        base = self._output_file or "sedf_report"
        base = os.path.splitext(base)[0]  # strip extension; we'll add ours

        fmt = self._fmt

        if fmt in ("json", "all") or (self._output_file and self._output_file.endswith(".json")):
            self._write_json(f"{base}.json", elapsed)

        if fmt in ("csv", "all") or (self._output_file and self._output_file.endswith(".csv")):
            self._write_csv(f"{base}.csv")

        if fmt in ("terminal", "all") or (self._output_file and self._output_file.endswith(".txt")):
            self._write_txt(f"{base}.txt", elapsed)

    def _write_json(self, path: str, elapsed: float):
        data = {
            "tool": "SEDF - SSRF Exploitation and Defense Framework",
            "version": "1.0.0",
            "scan_duration_seconds": round(elapsed, 2),
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.scan_start)),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        logger.info(f"JSON report written to: {path}")

    def _write_csv(self, path: str):
        if not self.findings:
            logger.info("No findings to write to CSV.")
            return
        fieldnames = [
            "severity", "url", "param", "payload", "evidence",
            "response_code", "response_time", "timestamp_iso", "remediation"
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for f in self.findings:
                writer.writerow(f.to_dict())
        logger.info(f"CSV report written to: {path}")

    def _write_txt(self, path: str, elapsed: float):
        lines = [
            "SEDF - SSRF Exploitation and Defense Framework",
            f"Scan Duration: {elapsed:.1f}s",
            f"Total Findings: {len(self.findings)}",
            "=" * 60,
        ]
        for i, f in enumerate(self.findings, 1):
            lines += [
                f"\nFinding #{i}",
                f"  Severity  : {f.severity.value}",
                f"  URL       : {f.url}",
                f"  Parameter : {f.param}",
                f"  Payload   : {f.payload}",
                f"  Evidence  : {f.evidence}",
                f"  HTTP Code : {f.response_code}",
                f"  Remediation: {f.remediation}",
            ]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        logger.info(f"Text report written to: {path}")
