"""
config.py — Configuration centrale du WAF personnalisé
"""
import os

# ─── Cible du reverse proxy ───────────────────────────────────────────────────
TARGET_URL = os.environ.get("TARGET_URL", "http://localhost:8888")

# ─── Serveur WAF ─────────────────────────────────────────────────────────────
WAF_HOST = os.environ.get("WAF_HOST", "0.0.0.0")
WAF_PORT = int(os.environ.get("WAF_PORT", 8080))

# ─── Mode de fonctionnement ───────────────────────────────────────────────────
# "block"   → bloque la requête et retourne 403
# "monitor" → laisse passer mais journalise quand même
WAF_MODE = os.environ.get("WAF_MODE", "block")

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_FILE = os.environ.get("LOG_FILE", "logs/waf_alerts.json")
LOG_CONSOLE = True   # Affichage coloré en console

# ─── Rate Limiting (anti brute-force) ─────────────────────────────────────────
RATE_LIMIT_ENABLED = False
RATE_LIMIT_WINDOW  = 60      # fenêtre de temps en secondes
RATE_LIMIT_MAX_REQ = 30      # max requêtes par IP dans la fenêtre
RATE_LIMIT_BAN_TTL = 300     # durée de ban en secondes (5 min)

# ─── IPs toujours autorisées (whitelist) ──────────────────────────────────────
IP_WHITELIST = [
    "127.0.0.1",
    "::1",
]

# ─── IPs toujours bloquées (blacklist) ────────────────────────────────────────
IP_BLACKLIST = []
