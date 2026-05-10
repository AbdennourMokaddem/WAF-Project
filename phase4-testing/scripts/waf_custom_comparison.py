import requests
import sys
from typing import List, Dict

# ─── Configuration des cibles ────────────────────────────────────────────────
TARGETS = {
    "Sans WAF (Direct)": "http://localhost:8080",
    "Custom WAF (Phase 3)": "http://localhost:8888",
}

# Cookie par défaut pour DVWA (sécurité basse pour les tests)
COOKIES = {"security": "low", "PHPSESSID": "test_session_id"}

# ─── Payloads de test ────────────────────────────────────────────────────────
TEST_CASES = [
    # --- SQL Injection ---
    {"name": "SQLi - Classic OR 1=1", "zone": "vulnerabilities/sqli/", "param": "id", "payload": "1' OR '1'='1", "type": "SQLi"},
    {"name": "SQLi - Union Select",   "zone": "vulnerabilities/sqli/", "param": "id", "payload": "' UNION SELECT user,password FROM users --", "type": "SQLi"},
    {"name": "SQLi - Time Based",    "zone": "vulnerabilities/sqli/", "param": "id", "payload": "1' AND SLEEP(5) --", "type": "SQLi"},
    
    # --- Cross-Site Scripting (XSS) ---
    {"name": "XSS - Basic Script",   "zone": "vulnerabilities/xss_r/", "param": "name", "payload": "<script>alert(1)</script>", "type": "XSS"},
    {"name": "XSS - Image Onerror",  "zone": "vulnerabilities/xss_r/", "param": "name", "payload": "<img src=x onerror=alert(1)>", "type": "XSS"},
    {"name": "XSS - SVG Onload",     "zone": "vulnerabilities/xss_r/", "param": "name", "payload": "<svg/onload=alert(1)>", "type": "XSS"},

    # --- Local File Inclusion (LFI) ---
    {"name": "LFI - Passwd File",    "zone": "vulnerabilities/fi/", "param": "page", "payload": "../../../../../etc/passwd", "type": "LFI"},
    {"name": "LFI - PHP Filter",     "zone": "vulnerabilities/fi/", "param": "page", "payload": "php://filter/convert.base64-encode/resource=index.php", "type": "LFI"},

    # --- Command Injection ---
    {"name": "CMDi - Semicolon ls",  "zone": "vulnerabilities/exec/", "param": "ip", "payload": "127.0.0.1; ls -la", "type": "CMDi"},
    {"name": "CMDi - Pipe whoami",   "zone": "vulnerabilities/exec/", "param": "ip", "payload": "127.0.0.1 | whoami", "type": "CMDi"},
]

def run_test(target_url: str, test: Dict) -> bool:
    """Retourne True si la requête a été BLOQUÉE (403), False sinon."""
    url = f"{target_url.rstrip('/')}/{test['zone'].lstrip('/')}"
    params = {test['param']: test['payload'], "Submit": "Submit"}
    
    try:
        response = requests.get(url, params=params, cookies=COOKIES, timeout=5)
        # On considère bloqué si le code est 403 (standard WAF)
        return response.status_code == 403
    except Exception:
        return False

def main():
    print("\n" + "="*80)
    print("      🧪 WAF COMPARATOR — PHASE 4 : ANALYSE DES PERFORMANCES")
    print("="*80 + "\n")

    results = {name: {"blocked": 0, "total": 0} for name in TARGETS}
    table_data = []

    for test in TEST_CASES:
        row = {"Test": test["name"], "Type": test["type"]}
        for name, base_url in TARGETS.items():
            is_blocked = run_test(base_url, test)
            row[name] = "✅ BLOQUÉ" if is_blocked else "❌ PASSÉ"
            results[name]["total"] += 1
            if is_blocked:
                results[name]["blocked"] += 1
        table_data.append(row)

    # Affichage du tableau
    header = f"{'Nom du Test':<30} | {'Type':<6} | {'Sans WAF (Direct)':<20} | {'Custom WAF (Phase 3)'}"
    print(header)
    print("-" * len(header))
    
    for r in table_data:
        print(f"{r['Test']:<30} | {r['Type']:<6} | {r['Sans WAF (Direct)']:<20} | {r['Custom WAF (Phase 3)']}")

    print("\n" + "="*80)
    print("      📊 RÉSUMÉ DES SCORES (Taux de blocage)")
    print("="*80)
    for name, stats in results.items():
        rate = (stats["blocked"] / stats["total"]) * 100
        color = "\033[92m" if rate > 80 else "\033[93m" if rate > 0 else "\033[91m"
        print(f"{name:<25} : {color}{rate:>5.1f}% de blocage\033[0m ({stats['blocked']}/{stats['total']})")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
