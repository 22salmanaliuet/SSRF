"""
DevCorp Toolkit - Vulnerable SSRF Lab
Intentionally vulnerable Flask app disguised as a real SaaS product.
DO NOT DEPLOY ON PUBLIC INTERNET.
"""

import os
import urllib.request
import urllib.parse
import urllib.error
import socket
from flask import Flask, request, jsonify, render_template_string, redirect

app = Flask(__name__)
app.config["DEBUG"] = False

# ── HTML Templates ────────────────────────────────────────────────────────────

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevCorp Toolkit</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        dark: '#0f1117',
                        card: '#1a1d27',
                        primary: '#3b82f6'
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-dark text-gray-300 font-sans antialiased">
    <div class="flex h-screen">
        
        <!-- Sidebar -->
        <div class="w-64 bg-card border-r border-gray-800 p-6 flex flex-col">
            <h1 class="text-2xl font-bold text-white flex items-center gap-2">
                <span class="text-primary">⚡</span> DevCorp
            </h1>
            <p class="text-xs text-red-500 font-bold mt-1 tracking-widest uppercase">Vulnerable Lab</p>
            
            <nav class="mt-10 flex-1 space-y-2">
                <a href="#profile" class="block px-4 py-2 rounded-lg bg-primary/10 text-primary font-medium">User Profile</a>
                <a href="#chat" class="block px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800">Chat Previews</a>
                <a href="#webhooks" class="block px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800">Integrations</a>
                <a href="#billing" class="block px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800">Billing & PDF</a>
                <a href="#sso" class="block px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800">SSO Login</a>
                <a href="#admin" class="block px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800">Admin Health</a>
                <a href="#themes" class="block px-4 py-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800">Themes</a>
            </nav>
        </div>

        <!-- Main Content -->
        <div class="flex-1 p-10 overflow-auto scroll-smooth">
            
            <div class="max-w-4xl space-y-12 pb-20">
                
                <!-- 1. Profile Avatar (Image Proxy) -->
                <section id="profile" class="bg-card border border-gray-800 p-8 rounded-2xl shadow-xl scroll-mt-10">
                    <h2 class="text-2xl font-bold text-white mb-2">Profile Settings</h2>
                    <p class="text-gray-400 mb-6">Update your avatar by providing a URL. Our servers will fetch and proxy the image for you.</p>
                    
                    <div class="flex items-center gap-6">
                        <div class="w-24 h-24 rounded-full bg-gray-800 border-2 border-gray-700 flex items-center justify-center overflow-hidden">
                            <span class="text-gray-500">No Img</span>
                        </div>
                        <div class="flex-1">
                            <form onsubmit="event.preventDefault(); const url = document.getElementById('avatar-url').value; window.open('/api/profile/avatar?url=' + encodeURIComponent(url), '_blank');">
                                <label class="block text-sm font-medium text-gray-400 mb-1">Avatar URL</label>
                                <div class="flex gap-2">
                                    <input id="avatar-url" type="url" placeholder="https://example.com/avatar.jpg" class="flex-1 bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary" required>
                                    <button type="submit" class="bg-primary hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium transition-colors">Fetch Image</button>
                                </div>
                            </form>
                            <p class="text-xs text-red-400 mt-2">Vulnerability: Image Proxy SSRF</p>
                        </div>
                    </div>
                </section>

                <!-- 2. Link Preview (Basic Fetch) -->
                <section id="chat" class="bg-card border border-gray-800 p-8 rounded-2xl shadow-xl scroll-mt-10">
                    <h2 class="text-2xl font-bold text-white mb-2">Chat Link Previewer</h2>
                    <p class="text-gray-400 mb-6">Test our link unfurling microservice. We scrape the target URL to generate a rich preview card.</p>
                    
                    <form onsubmit="event.preventDefault(); const url = document.getElementById('preview-url').value; window.open('/api/preview/link?url=' + encodeURIComponent(url), '_blank');">
                        <label class="block text-sm font-medium text-gray-400 mb-1">Message URL</label>
                        <div class="flex gap-2">
                            <input id="preview-url" type="url" placeholder="https://example.com" class="flex-1 bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary" required>
                            <button type="submit" class="bg-primary hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium transition-colors">Generate Preview</button>
                        </div>
                    </form>
                    <p class="text-xs text-red-400 mt-2">Vulnerability: Basic Full-Response SSRF</p>
                </section>

                <!-- 3. Webhooks (POST) -->
                <section id="webhooks" class="bg-card border border-gray-800 p-8 rounded-2xl shadow-xl scroll-mt-10">
                    <h2 class="text-2xl font-bold text-white mb-2">Developer Integrations</h2>
                    <p class="text-gray-400 mb-6">Configure a webhook to receive real-time events. We'll send a test POST payload immediately.</p>
                    
                    <form onsubmit="event.preventDefault(); const url = document.getElementById('webhook-url').value; fetch('/api/settings/webhook', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({target_endpoint: url})}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)));">
                        <label class="block text-sm font-medium text-gray-400 mb-1">Webhook Target URL</label>
                        <div class="flex gap-2">
                            <input id="webhook-url" type="url" placeholder="https://your-server.com/webhook" class="flex-1 bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary" required>
                            <button type="submit" class="bg-primary hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium transition-colors">Send Test Event</button>
                        </div>
                    </form>
                    <p class="text-xs text-red-400 mt-2">Vulnerability: POST-based SSRF</p>
                </section>

                <!-- 4. Billing PDF (Blind SSRF) -->
                <section id="billing" class="bg-card border border-gray-800 p-8 rounded-2xl shadow-xl scroll-mt-10 relative overflow-hidden">
                    <div class="absolute top-0 right-0 bg-red-500 text-white text-xs font-bold px-3 py-1 rounded-bl-lg">BLIND SSRF</div>
                    <h2 class="text-2xl font-bold text-white mb-2">Invoice Exporter</h2>
                    <p class="text-gray-400 mb-6">Generate a PDF invoice for your clients. Provide a URL to your company logo to embed it in the PDF.</p>
                    
                    <form onsubmit="event.preventDefault(); const url = document.getElementById('logo-url').value; fetch('/api/billing/export-invoice', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({logo_url: url})}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)));">
                        <label class="block text-sm font-medium text-gray-400 mb-1">Company Logo URL</label>
                        <div class="flex gap-2">
                            <input id="logo-url" type="url" placeholder="https://example.com/logo.png" class="flex-1 bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary" required>
                            <button type="submit" class="bg-primary hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium transition-colors">Queue PDF Generation</button>
                        </div>
                    </form>
                    <p class="text-xs text-red-400 mt-2">Vulnerability: Blind SSRF (Background processing, no output returned)</p>
                </section>

                <!-- 5. SSO Login (Redirect) -->
                <section id="sso" class="bg-card border border-gray-800 p-8 rounded-2xl shadow-xl scroll-mt-10">
                    <h2 class="text-2xl font-bold text-white mb-2">SSO Authentication</h2>
                    <p class="text-gray-400 mb-6">Login via DevCorp SSO. After successful login, you will be redirected to the 'continue' URL.</p>
                    
                    <form onsubmit="event.preventDefault(); const url = document.getElementById('sso-url').value; window.open('/auth/login?continue=' + encodeURIComponent(url), '_blank');">
                        <label class="block text-sm font-medium text-gray-400 mb-1">Redirect URL (continue)</label>
                        <div class="flex gap-2">
                            <input id="sso-url" type="url" value="http://example.com/dashboard" class="flex-1 bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary" required>
                            <button type="submit" class="bg-primary hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium transition-colors">Login with SSO</button>
                        </div>
                    </form>
                    <p class="text-xs text-red-400 mt-2">Vulnerability: Open Redirect -> SSRF (Backend follows redirect)</p>
                </section>

                <!-- 6. Admin Health (Internal Proxy) -->
                <section id="admin" class="bg-card border border-gray-800 p-8 rounded-2xl shadow-xl scroll-mt-10">
                    <h2 class="text-2xl font-bold text-white mb-2">Service Health Monitor</h2>
                    <p class="text-gray-400 mb-6">Check the health of our internal microservices. The proxy adds required internal auth headers.</p>
                    
                    <form onsubmit="event.preventDefault(); const url = document.getElementById('health-url').value; window.open('/admin/health?service_url=' + encodeURIComponent(url), '_blank');">
                        <label class="block text-sm font-medium text-gray-400 mb-1">Service URL</label>
                        <div class="flex gap-2">
                            <input id="health-url" type="url" value="http://internal-billing-service/status" class="flex-1 bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary" required>
                            <button type="submit" class="bg-primary hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium transition-colors">Check Health</button>
                        </div>
                    </form>
                    <p class="text-xs text-red-400 mt-2">Vulnerability: Authenticated Internal SSRF</p>
                </section>

                <!-- 7. Themes (File Read) -->
                <section id="themes" class="bg-card border border-gray-800 p-8 rounded-2xl shadow-xl scroll-mt-10">
                    <h2 class="text-2xl font-bold text-white mb-2">Custom Themes</h2>
                    <p class="text-gray-400 mb-6">Load custom CSS theme configurations. Supports local system paths for pre-installed themes.</p>
                    
                    <form onsubmit="event.preventDefault(); const url = document.getElementById('theme-url').value; window.open('/api/theme/load?source=' + encodeURIComponent(url), '_blank');">
                        <label class="block text-sm font-medium text-gray-400 mb-1">Theme Source / Path</label>
                        <div class="flex gap-2">
                            <input id="theme-url" type="text" value="/etc/hosts" class="flex-1 bg-[#0a0c10] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-primary" required>
                            <button type="submit" class="bg-primary hover:bg-blue-600 text-white px-6 py-2 rounded-lg font-medium transition-colors">Load Theme</button>
                        </div>
                    </form>
                    <p class="text-xs text-red-400 mt-2">Vulnerability: Local File Read / Path Traversal</p>
                </section>

                <!-- Mitigated -->
                <section class="bg-card border border-green-900/50 p-8 rounded-2xl shadow-xl scroll-mt-10">
                    <h2 class="text-2xl font-bold text-green-400 mb-2">🛡 Mitigated Feature</h2>
                    <p class="text-gray-400 mb-6">This endpoint implements a strict URL allowlist and blocks private IP ranges. Use it for defense testing.</p>
                    
                    <div class="bg-[#0a0c10] rounded-lg p-3 overflow-x-auto border border-gray-800">
                        <code class="text-green-400 text-sm">GET /safe-fetch?url=http://example.com</code>
                    </div>
                </section>

            </div>
        </div>
    </div>
</body>
</html>
"""


# ── Vulnerable Endpoints (Realistic Business Logic) ───────────────────────────

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/api/profile/avatar")
def profile_avatar():
    """
    FR-01 target: Image Proxy.
    Simulates fetching a user's profile picture from a URL.
    """
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DevCorp-Image-Fetcher/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            content_type = resp.headers.get("Content-Type", "application/octet-stream")
            data = resp.read(1_000_000)
            from flask import Response
            return Response(data, content_type=content_type)
    except Exception as exc:
        return jsonify({"error": "Avatar fetch failed", "details": str(exc)}), 500


@app.route("/api/preview/link")
def link_preview():
    """
    FR-01 target: Basic Full-Response SSRF.
    Simulates chat link unfurling / scraping.
    """
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DevCorp-LinkBot/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(10_000).decode("utf-8", errors="replace")
            # In a real app, this would parse HTML meta tags. We just dump it.
            return jsonify({
                "preview_target": url,
                "scraped_title": "Found title tag",
                "scraped_body_snippet": body[:2000],
                "response_code": resp.status
            })
    except urllib.error.URLError as exc:
        return jsonify({"error": str(exc)}), 200 # Leaks error
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/settings/webhook", methods=["POST"])
def webhook():
    """
    FR-02 target: POST SSRF.
    Simulates webhook registration.
    """
    endpoint = request.form.get("target_endpoint") or request.json.get("target_endpoint", "") if request.is_json else request.form.get("target_endpoint", "")
    if not endpoint:
        return jsonify({"error": "Missing 'target_endpoint' parameter"}), 400

    try:
        req = urllib.request.Request(
            endpoint,
            data=b'{"event": "ping", "message": "DevCorp Webhook Verification"}',
            headers={"Content-Type": "application/json", "X-DevCorp-Signature": "v1=a8b3c9"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return jsonify({"status": "success", "http_code": resp.status, "message": f"Webhook test sent to {endpoint}"})
    except Exception as exc:
        return jsonify({"status": "failed", "error": str(exc), "endpoint": endpoint}), 500


@app.route("/api/billing/export-invoice", methods=["POST", "GET"])
def blind_ssrf_pdf():
    """
    FR-03 target: Blind SSRF.
    Simulates PDF invoice generation with a custom logo.
    """
    url = request.args.get("logo_url")
    if not url and request.is_json:
        url = request.json.get("logo_url", "")
    elif not url and request.form:
        url = request.form.get("logo_url", "")
        
    if not url:
        return jsonify({"status": "error", "message": "Missing 'logo_url' parameter"}), 400

    # Simulates background fetching
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DevCorp-PDFEngine/2.1"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            resp.read() # Discard output
    except Exception:
        pass # Truly blind, ignore all errors

    return jsonify({
        "status": "queued",
        "message": "Invoice generation started. It will be emailed to you shortly.",
        "task_id": "inv_84729472a8c"
    }), 202


@app.route("/auth/login")
def redirect_endpoint():
    """
    FR-04 target: Open Redirect leading to SSRF.
    Simulates SSO login return flow.
    """
    next_url = request.args.get("continue", "")
    if not next_url:
        return jsonify({"error": "Missing 'continue' parameter"}), 400

    try:
        # Instead of just a 302, the vulnerable backend tries to pre-fetch the next URL
        # for "SSO validation" before redirecting (a common architectural flaw).
        req = urllib.request.Request(next_url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(5000).decode("utf-8", errors="replace")
            # Simulating the flaw: it returns the body of the target site instead of a 302
            return jsonify({
                "message": "SSO Login Success. Pre-loaded destination context.",
                "destination_data": body[:500]
            })
    except Exception as exc:
        return jsonify({"error": f"SSO redirect validation failed: {exc}"}), 500


@app.route("/admin/health")
def api_proxy():
    """
    FR-05 target: Internal API Proxy.
    Simulates a health-check dashboard for internal microservices.
    """
    api_url = request.args.get("service_url", "")
    if not api_url:
        return jsonify({"error": "Missing 'service_url' parameter"}), 400

    try:
        # Adds sensitive internal headers
        req = urllib.request.Request(api_url, headers={
            "X-Internal-Auth": "super-secret-admin-token",
            "X-Forwarded-For": "127.0.0.1"
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(10_000).decode("utf-8", errors="replace")
            return jsonify({
                "service": api_url,
                "status": "healthy" if resp.status == 200 else "degraded",
                "health_response": body
            })
    except Exception as exc:
        return jsonify({"error": str(exc), "service": api_url, "status": "down"}), 500


@app.route("/api/theme/load")
def file_read():
    """
    FR-07 target: File Read / Path Traversal.
    Simulates loading a theme configuration file.
    """
    path = request.args.get("source", "/etc/hostname")
    try:
        # Vulnerable to local file read
        with open(path, "r") as fh:
            return jsonify({"theme_loaded": path, "css_content": fh.read(5000)})
    except Exception as exc:
        return jsonify({"error": "Theme load failed", "details": str(exc)}), 500


# ── Mitigated Endpoint ────────────────────────────────────────────────────────

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
    return False


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
        return jsonify({"error": "Fetch failed"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] DevCorp Toolkit Lab running on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
