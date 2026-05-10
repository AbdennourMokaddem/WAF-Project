#!/usr/bin/env python3
"""
================================================
Custom WAF — Phase 3
Auteur  : [Prénom Ami]
Langage : Python
================================================
Architecture : Reverse Proxy + Inspection Engine

Fonctionnalités :
  - Traffic Interception (reverse proxy HTTP)
  - Inspection URI + Headers + Body
  - Détection SQLi via regex
  - Détection XSS via regex
  - Réponse 403 avec page HTML custom
  - Logging des attaques bloquées
================================================
"""

import http.server
import urllib.request
import urllib.parse
import re
import json
import logging
from datetime import datetime
from typing import Optional

# ================================================
# CONFIGURATION
# ================================================
WAF_HOST = "0.0.0.0"
WAF_PORT = 8888
BACKEND_URL = "http://localhost:8080"   # DVWA
LOG_FILE = "logs/waf_blocked.log"

# ================================================
# RÈGLES DE DÉTECTION
# ================================================
SQLI_PATTERNS = [
    r"(?i)(union\s+select)",
    r"(?i)('\s*or\s*'?\d+'?\s*=\s*'?\d+)",
    r"(?i)(or\s+1\s*=\s*1)",
    r"(?i)(drop\s+table)",
    r"(?i)(insert\s+into)",
    r"(?i)(select\s+.*\s+from)",
    r"(?i)(--\s*$)",
    r"(?i)(;\s*drop|;\s*delete|;\s*insert)",
    r"(?i)(sleep\s*\()",
    r"(?i)(benchmark\s*\()",
]

XSS_PATTERNS = [
    r"(?i)(<script[\s>])",
    r"(?i)(</script>)",
    r"(?i)(javascript\s*:)",
    r"(?i)(on(load|error|click|mouseover|focus)\s*=)",
    r"(?i)(<img[^>]+onerror)",
    r"(?i)(<svg[^>]+onload)",
    r"(?i)(<iframe)",
    r"(?i)(document\.cookie)",
    r"(?i)(alert\s*\()",
]

RULES = {
    "SQLi": SQLI_PATTERNS,
    "XSS": XSS_PATTERNS,
}

# ================================================
# LOGGING
# ================================================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(message)s"
)

def log_blocked(ip: str, rule: str, payload: str, uri: str):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "attacker_ip": ip,
        "triggered_rule": rule,
        "malicious_payload": payload[:200],
        "uri": uri,
    }
    logging.info(json.dumps(entry))
    print(f"[BLOCKED] {entry['timestamp']} | {ip} | {rule} | {uri}")

# ================================================
# MOTEUR D'INSPECTION
# ================================================
def inspect(value: str) -> Optional[tuple]:
    """
    Inspecte une valeur et retourne (rule_name, payload) si attaque détectée.
    Retourne None si la valeur est sûre.
    """
    for rule_name, patterns in RULES.items():
        for pattern in patterns:
            if re.search(pattern, value):
                return (rule_name, value)
    return None

def check_request(uri: str, headers: dict, body: str) -> Optional[tuple]:
    """
    Vérifie l'URI, les headers et le body.
    Retourne (rule, payload) si attaque trouvée.
    """
    # Inspecter l'URI
    decoded_uri = urllib.parse.unquote(uri)
    result = inspect(decoded_uri)
    if result:
        return result

    # Inspecter les headers
    for header_name, header_value in headers.items():
        if header_name.lower() in ["user-agent", "referer", "x-forwarded-for"]:
            result = inspect(header_value)
            if result:
                return result

    # Inspecter le body (POST data)
    if body:
        decoded_body = urllib.parse.unquote(body)
        result = inspect(decoded_body)
        if result:
            return result

    return None

# ================================================
# PAGE DE BLOCAGE (403)
# ================================================
BLOCK_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>403 — Accès Refusé</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #1a1a2e; color: #eee;
                display: flex; align-items: center; justify-content: center;
                height: 100vh; margin: 0; }}
        .box {{ background: #16213e; border: 2px solid #e94560;
                border-radius: 10px; padding: 40px; text-align: center;
                max-width: 500px; }}
        h1 {{ color: #e94560; font-size: 3em; margin: 0; }}
        h2 {{ color: #e94560; margin-top: 5px; }}
        p  {{ color: #aaa; }}
        .badge {{ background: #e94560; color: white; padding: 5px 15px;
                  border-radius: 20px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>🛡️ 403</h1>
        <h2>Accès Refusé</h2>
        <p>Votre requête a été bloquée par le WAF.</p>
        <p><span class="badge">Règle déclenchée : {rule}</span></p>
        <p style="font-size:0.8em; color:#666;">Custom WAF — Phase 3 | ENSAM Casablanca</p>
    </div>
</body>
</html>"""

# ================================================
# HANDLER HTTP
# ================================================
class WAFHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        self._handle_request(method="GET")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        self._handle_request(method="POST", body=body)

    def _handle_request(self, method: str, body: str = ""):
        client_ip = self.client_address[0]
        uri = self.path
        headers = dict(self.headers)

        # === INSPECTION ===
        detection = check_request(uri, headers, body)

        if detection:
            rule_name, payload = detection
            log_blocked(client_ip, rule_name, payload, uri)
            self._send_block(rule_name)
            return

        # === FORWARD vers le backend ===
        self._proxy_request(method, body)

    def _send_block(self, rule: str):
        page = BLOCK_PAGE.format(rule=rule).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("X-WAF-Blocked", "true")
        self.end_headers()
        self.wfile.write(page)

    def _proxy_request(self, method: str, body: str = ""):
        target_url = BACKEND_URL + self.path
        try:
            data = body.encode("utf-8") if body else None
            req = urllib.request.Request(target_url, data=data, method=method)

            for key, value in self.headers.items():
                if key.lower() not in ["host", "content-length"]:
                    req.add_header(key, value)

            with urllib.request.urlopen(req, timeout=10) as response:
                self.send_response(response.status)
                for key, value in response.headers.items():
                    if key.lower() not in ["transfer-encoding"]:
                        self.send_header(key, value)
                self.end_headers()
                self.wfile.write(response.read())

        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Bad Gateway: {e}".encode())

    def log_message(self, format, *args):
        pass  # Désactiver les logs console par défaut

# ================================================
# MAIN
# ================================================
if __name__ == "__main__":
    import os
    os.makedirs("logs", exist_ok=True)

    print(f"""
    ╔══════════════════════════════════════╗
    ║      Custom WAF — Phase 3            ║
    ║      ENSAM Casablanca                ║
    ╠══════════════════════════════════════╣
    ║  WAF Port    : {WAF_PORT}                  ║
    ║  Backend     : {BACKEND_URL}    ║
    ║  Log file    : {LOG_FILE}   ║
    ╚══════════════════════════════════════╝
    """)

    server = http.server.HTTPServer((WAF_HOST, WAF_PORT), WAFHandler)
    print(f"[*] WAF démarré sur http://{WAF_HOST}:{WAF_PORT}")
    print(f"[*] Appuyer sur Ctrl+C pour arrêter\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] WAF arrêté.")
        server.shutdown()
