"""
Vulnerable SSRF Lab Application

Intentionally vulnerable Flask app for SEDF testing.
Contains multiple SSRF vulnerability patterns for educational demonstration.

DO NOT DEPLOY ON PUBLIC INTERNET.
"""

import os
import urllib.request
import urllib.parse
import urllib.error
import socket
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)
app.config["DEBUG"] = False

# ── HTML Templates ────────────────────────────────────────────────────────────

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Vulnerable Lab</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 2rem; }
        h1 { color: #e94560; }
        h2 { color: #0f3460; background: #e94560; padding: 0.3rem 0.6rem; }
        a { color: #4ecca3; }
        pre { background: #16213e; padding: 1rem; border-radius: 4px; overflow-x: auto; }
        .warn { background: #7f0000; padding: 0.5rem 1rem; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>⚠ SEDF - Vulnerable Lab</h1>
    <p class="warn">⚠ FOR EDUCATIONAL USE ONLY — NOT FOR PRODUCTION</p>

    <h2>Vulnerable Endpoints</h2>

    <h3>1. Basic URL Fetch (GET param)</h3>
    <pre>GET /fetch?url=http://example.com</pre>
    <p>SSRF via: <a href="/fetch?url=http://127.0.0.1">/fetch?url=http://127.0.0.1</a></p>

    <h3>2. Image Proxy (GET param)</h3>
    <pre>GET /image?src=http://example.com/img.png</pre>
    <p>SSRF via: <a href="/image?src=http://127.0.0.1">/image?src=http://127.0.0.1</a></p>

    <h3>3. Webhook URL (POST param)</h3>
    <pre>POST /webhook  body: endpoint=http://example.com</pre>

    <h3>4. Redirect Endpoint</h3>
    <pre>GET /redirect?next=http://example.com</pre>

    <h3>5. Internal API (simulated)</h3>
    <pre>GET /api/proxy?api_url=http://internal-service/data</pre>

    <h3>6. File Read (blind SSRF indicator)</h3>
    <pre>GET /read?path=/etc/hosts</pre>

    <h2>Mitigated Endpoint (for --defense testing)</h2>
    <pre>GET /safe-fetch?url=http://example.com</pre>
</body>
</html>
"""


# ── Vulnerable Endpoints ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/fetch")
def fetch():
    """
    FR-01 target: Basic SSRF — fetches any URL the user provides.
    Vulnerable parameter: url
    """
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LabApp/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(10_000).decode("utf-8", errors="replace")
            return jsonify({
                "url": url,
                "status": resp.status,
                "body_snippet": body[:2000],
                "headers": dict(resp.headers),
            })
    except urllib.error.URLError as exc:
        # Intentionally leaks error messages (information disclosure)
        return jsonify({"error": str(exc)}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/image")
def image_proxy():
    """Vulnerable image proxy — SSRF via 'src' parameter."""
    src = request.args.get("src", "")
    if not src:
        return jsonify({"error": "Missing 'src' parameter"}), 400

    try:
        req = urllib.request.Request(src)
        with urllib.request.urlopen(req, timeout=5) as resp:
            content_type = resp.headers.get("Content-Type", "application/octet-stream")
            data = resp.read(1_000_000)
            from flask import Response
            return Response(data, content_type=content_type)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/webhook", methods=["POST"])
def webhook():
    """Vulnerable webhook endpoint — SSRF via 'endpoint' POST parameter."""
    endpoint = request.form.get("endpoint") or request.json.get("endpoint", "") if request.is_json else request.form.get("endpoint", "")
    if not endpoint:
        return jsonify({"error": "Missing 'endpoint' parameter"}), 400

    try:
        req = urllib.request.Request(
            endpoint,
            data=b'{"event": "test"}',
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return jsonify({"status": resp.status, "sent_to": endpoint})
    except Exception as exc:
        return jsonify({"error": str(exc), "endpoint": endpoint}), 500


@app.route("/redirect")
def redirect_endpoint():
    """Open redirect + SSRF combo — 'next' parameter followed naively."""
    next_url = request.args.get("next", "")
    if not next_url:
        return jsonify({"error": "Missing 'next' parameter"}), 400

    try:
        req = urllib.request.Request(next_url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(5000).decode("utf-8", errors="replace")
            return jsonify({"redirected_to": next_url, "body": body[:500]})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/proxy")
def api_proxy():
    """Internal API proxy — SSRF via 'api_url' parameter."""
    api_url = request.args.get("api_url", "")
    if not api_url:
        return jsonify({"error": "Missing 'api_url' parameter"}), 400

    try:
        req = urllib.request.Request(api_url, headers={"X-Internal": "true"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(10_000).decode("utf-8", errors="replace")
            return jsonify({"api_response": body, "source": api_url})
    except Exception as exc:
        return jsonify({"error": str(exc), "attempted_url": api_url}), 500


@app.route("/read")
def file_read():
    """
    Local file read endpoint (simulates SSRF + file:// interaction).
    Vulnerable to path traversal AND SSRF-triggered file disclosure.
    """
    path = request.args.get("path", "/etc/hostname")
    try:
        with open(path, "r") as fh:
            return jsonify({"path": path, "content": fh.read(5000)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Mitigated Endpoint (for defense testing) ──────────────────────────────────

ALLOWED_HOSTS = {"example.com", "httpbin.org"}

PRIVATE_RANGES_CIDR = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "0.", "169.254.",
]


def is_safe_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    hostname = parsed.hostname or ""
    if hostname in ALLOWED_HOSTS:
        return True
    try:
        ip = socket.gethostbyname(hostname)
        for prefix in PRIVATE_RANGES_CIDR:
            if ip.startswith(prefix):
                return False
    except Exception:
        return False
    return False  # Strict allowlist: deny if not in ALLOWED_HOSTS


@app.route("/safe-fetch")
def safe_fetch():
    """Mitigated endpoint — validates URL before fetching."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    if not is_safe_url(url):
        return jsonify({"error": "URL not permitted by security policy"}), 403

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(5000).decode("utf-8", errors="replace")
            return jsonify({"body": body[:500]})
    except Exception as exc:
        return jsonify({"error": "Fetch failed"}), 500   # Sanitized error


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] SSRF Lab running on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
