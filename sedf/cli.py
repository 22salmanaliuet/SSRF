"""
sedf/cli.py - Command-line interface and argument parsing for SEDF
"""

import argparse
import sys
import os
from sedf.utils.banner import print_banner, print_disclaimer
from sedf.utils.logger import setup_logger, get_logger
from sedf.scanner import Scanner
from sedf.modules.defense import DefenseChecker
from sedf.reporting.reporter import Reporter

logger = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ssrfcli",
        description="SEDF - SSRF Exploitation and Defense Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssrfcli.py -u "http://site/?url=FUZZ" --payloads default
  python ssrfcli.py -u targets.txt --threads 10 --output report.json
  python ssrfcli.py -u "http://site/?url=FUZZ" --oob-domain mylab.com
  python ssrfcli.py -u "http://site/?url=FUZZ" --exploit --module aws_meta
  python ssrfcli.py -u "http://site/?url=FUZZ" --defense
  python ssrfcli.py --lab                        (start vulnerable lab)

LEGAL NOTICE: For authorized and educational use only.
        """,
    )

    # ── Target ──────────────────────────────────────────────────────────────
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-u", "--url",
        metavar="URL",
        help="Target URL. Use FUZZ to mark injection point. "
             "Can be a .txt file with multiple URLs.",
    )

    # ── Payload ──────────────────────────────────────────────────────────────
    payload_group = parser.add_argument_group("Payloads")
    payload_group.add_argument(
        "--payloads",
        metavar="SET",
        default="default",
        choices=["default", "all", "http", "file", "gopher", "cloud", "bypass", "encoded"],
        help="Payload set to use (default: default)",
    )
    payload_group.add_argument(
        "--payload-file",
        metavar="FILE",
        help="Custom payload file (one payload per line)",
    )
    payload_group.add_argument(
        "--params",
        metavar="PARAMS",
        help="Comma-separated list of parameters to test (e.g. url,redirect,next)",
    )

    # ── Detection ────────────────────────────────────────────────────────────
    detection_group = parser.add_argument_group("Detection")
    detection_group.add_argument(
        "--oob-domain",
        metavar="DOMAIN",
        help="Domain for out-of-band (DNS/HTTP) callback detection",
    )
    detection_group.add_argument(
        "--callback-port",
        metavar="PORT",
        type=int,
        default=8888,
        help="Local port for HTTP callback server (default: 8888)",
    )
    detection_group.add_argument(
        "--blind",
        action="store_true",
        help="Enable blind SSRF detection mode (requires --oob-domain or local callback)",
    )

    # ── Exploitation ─────────────────────────────────────────────────────────
    exploit_group = parser.add_argument_group("Exploitation Modules")
    exploit_group.add_argument(
        "--exploit",
        action="store_true",
        help="Enable exploitation modules (requires explicit consent)",
    )
    exploit_group.add_argument(
        "--module",
        metavar="MODULE",
        choices=["aws_meta", "gcp_meta", "azure_meta", "redis", "file_read", "port_scan", "all"],
        help="Exploitation module to use",
    )
    exploit_group.add_argument(
        "--ports",
        metavar="PORTS",
        default="22,80,443,3306,6379,8080,8443",
        help="Comma-separated ports for port scan module (default: common ports)",
    )
    exploit_group.add_argument(
        "--internal-ip",
        metavar="IP",
        default="127.0.0.1",
        help="Internal IP to probe (default: 127.0.0.1)",
    )
    exploit_group.add_argument(
        "--exploit-ssrf",
        action="store_true",
        help="Run full SSRF exploitation: port recon + data extraction via confirmed injection point",
    )

    # ── Defense ──────────────────────────────────────────────────────────────
    defense_group = parser.add_argument_group("Defense Testing")
    defense_group.add_argument(
        "--defense",
        action="store_true",
        help="Run defensive testing module (checks mitigations in place)",
    )

    # ── Request settings ─────────────────────────────────────────────────────
    request_group = parser.add_argument_group("Request Settings")
    request_group.add_argument(
        "--threads",
        metavar="N",
        type=int,
        default=5,
        help="Number of concurrent threads (default: 5, max: 20)",
    )
    request_group.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    request_group.add_argument(
        "--delay",
        metavar="SECONDS",
        type=float,
        default=0.0,
        help="Delay between requests in seconds",
    )
    request_group.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)",
    )
    request_group.add_argument(
        "--headers",
        metavar="HEADERS",
        help='Additional headers as JSON string (e.g. \'{"X-Custom": "value"}\')',
    )
    request_group.add_argument(
        "--method",
        metavar="METHOD",
        default="GET",
        choices=["GET", "POST", "PUT"],
        help="HTTP method (default: GET)",
    )
    request_group.add_argument(
        "--data",
        metavar="DATA",
        help="POST body data (use FUZZ for injection point)",
    )
    request_group.add_argument(
        "--cookies",
        metavar="COOKIES",
        help="Cookies to include in requests",
    )

    # ── Output ───────────────────────────────────────────────────────────────
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Output file for report (supports .json, .csv, .txt)",
    )
    output_group.add_argument(
        "--format",
        metavar="FORMAT",
        default="terminal",
        choices=["terminal", "json", "csv", "all"],
        help="Report format (default: terminal)",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (only show findings)",
    )
    output_group.add_argument(
        "--extract",
        action="store_true",
        help="Show extracted response content for each vulnerability found (exploitation mode)",
    )

    # ── Safety ──────────────────────────────────────────────────────────────
    safety_group = parser.add_argument_group("Safety")
    safety_group.add_argument(
        "--safe-mode",
        action="store_true",
        default=True,
        help="Safe mode: prevent accidental external exploitation (default: ON)",
    )
    safety_group.add_argument(
        "--no-safe-mode",
        action="store_true",
        help="Disable safe mode (use only in authorized lab environments)",
    )
    safety_group.add_argument(
        "--confirm",
        action="store_true",
        help="Skip interactive confirmation prompts",
    )

    # ── Lab ──────────────────────────────────────────────────────────────────
    lab_group = parser.add_argument_group("Lab")
    lab_group.add_argument(
        "--lab",
        action="store_true",
        help="Start the local vulnerable lab environment (requires Docker)",
    )

    return parser


def confirm_action(message: str) -> bool:
    """Ask user for confirmation before proceeding with potentially risky actions."""
    print(f"\n[!] {message}")
    answer = input("    Do you confirm you have authorization? [y/N]: ").strip().lower()
    return answer == "y"


def validate_args(args: argparse.Namespace) -> bool:
    """Validate argument combinations and apply constraints."""
    errors = []

    # Thread limit
    if args.threads > 20:
        print("[!] Thread count capped at 20 (NFR-02). Setting to 20.")
        args.threads = 20

    # Safe mode logic
    if args.no_safe_mode:
        args.safe_mode = False

    # Must have target or lab
    if not args.url and not args.lab:
        errors.append("You must specify a target URL (-u) or use --lab to start the lab.")

    # Exploit requires confirmation
    if args.exploit and args.safe_mode:
        print("[!] Exploitation modules require --no-safe-mode in non-lab environments.")
        print("    Safe mode prevents accidental exploitation of unintended targets.")

    if errors:
        for e in errors:
            print(f"[ERROR] {e}")
        return False

    return True


def main():
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    # Handle --lab before anything else
    if args.lab:
        from sedf.utils.lab import start_lab
        start_lab()
        return

    if not validate_args(args):
        parser.print_usage()
        sys.exit(1)

    # Setup logging
    log_level = "DEBUG" if args.verbose else ("ERROR" if args.quiet else "INFO")
    setup_logger(log_level)

    # Show disclaimer for non-quiet mode
    if not args.quiet:
        print_disclaimer()

    # Require confirmation if not in quiet/confirm mode and not safe mode
    if not args.confirm and not args.quiet:
        if not confirm_action(
            f"You are about to scan: {args.url}\n"
            "    Ensure you have explicit written authorization to test this target."
        ):
            print("[*] Scan aborted by user.")
            sys.exit(0)

    # ── Run Scanner or Exploitation ────────────────────────────────────────────────
    reporter = Reporter(args)

    if args.defense:
        checker = DefenseChecker(args, reporter)
        checker.run()
        reporter.finalize()

    elif getattr(args, 'exploit_ssrf', False):
        # Full SSRF exploitation mode — has its own output/summary
        from sedf.modules.ssrf_exploit import SSRFExploiter
        from sedf.utils.http_client import HTTPClient
        client = HTTPClient(args)
        body_template = getattr(args, 'data', None)
        exploiter = SSRFExploiter(args, client, args.url, body_template)
        exploiter.run()
        # No reporter.finalize() here — exploit module has its own report

    else:
        scanner = Scanner(args, reporter)
        scanner.run()
        reporter.finalize()



if __name__ == "__main__":
    main()
