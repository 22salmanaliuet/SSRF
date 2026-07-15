"""
sedf/utils/lab.py - Docker lab startup helper.

Starts the bundled vulnerable web app container for safe local testing.
"""

import os
import subprocess
import sys

from sedf.utils.logger import get_logger

logger = get_logger(__name__)

DOCKER_COMPOSE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "docker", "docker-compose.yml"
)


def start_lab():
    """Launch the vulnerable lab using Docker Compose."""
    if not os.path.exists(DOCKER_COMPOSE_PATH):
        logger.error(f"docker-compose.yml not found at: {DOCKER_COMPOSE_PATH}")
        sys.exit(1)

    # Check Docker is available
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("[ERROR] Docker is not available or not running.")
        print("        Install Docker: https://docs.docker.com/get-docker/")
        sys.exit(1)

    print("[*] Starting SEDF vulnerable lab ...")
    print(f"    Compose file: {DOCKER_COMPOSE_PATH}\n")

    try:
        subprocess.run(
            ["docker", "compose", "-f", DOCKER_COMPOSE_PATH, "up", "--build", "-d"],
            check=True,
        )
        print("\n[✓] Lab started successfully!")
        print("    Vulnerable app : http://localhost:5000")
        print("    Stop lab       : docker compose -f docker/docker-compose.yml down\n")
        print("    Example scan:")
        print('    python ssrfcli.py -u "http://localhost:5000/fetch?url=FUZZ" --payloads default')
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] Failed to start lab: {exc}")
        sys.exit(1)
