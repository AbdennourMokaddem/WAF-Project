# Phase 3 — Custom WAF (Python)

**Responsable : [Prénom Ami]**

## Architecture

```
Client (Browser / ZAP)
        ↓
Custom WAF Python (port 8888)   ← Reverse Proxy + Inspection
        ↓
DVWA (port 8080)                ← App cible
```

## Fonctionnalités

| Fonctionnalité | Implémentée |
|----------------|-------------|
| Reverse Proxy HTTP | ✅ |
| Inspection URI | ✅ |
| Inspection Headers | ✅ |
| Inspection Body (POST) | ✅ |
| Détection SQLi (Regex) | ✅ |
| Détection XSS (Regex) | ✅ |
| Réponse 403 + page HTML custom | ✅ |
| Logging JSON structuré | ✅ |

## Démarrage

```bash
# Installer les dépendances (aucune lib externe requise)
python3 --version   # Python 3.10+ requis

# Lancer DVWA d'abord (Phase 1)
cd ../phase1-target
docker compose up -d
cd ../phase3-custom-waf

# Lancer le WAF
python3 waf.py

# Accéder à DVWA via le Custom WAF
# http://localhost:8888
```

## Format des logs

Chaque attaque bloquée est loggée en JSON dans `logs/waf_blocked.log` :

```json
{
  "timestamp": "2026-05-02T14:30:00Z",
  "attacker_ip": "127.0.0.1",
  "triggered_rule": "SQLi",
  "malicious_payload": "1 OR 1=1",
  "uri": "/vulnerabilities/sqli/?id=1+OR+1%3D1"
}
```

## Règles de détection

Les règles sont définies dans `waf.py` sous `SQLI_PATTERNS` et `XSS_PATTERNS`.

### SQLi détectée
- `UNION SELECT`
- `OR 1=1`
- `DROP TABLE`
- `SLEEP()` / `BENCHMARK()`
- etc.

### XSS détectée
- `<script>`
- `javascript:`
- `onerror=` / `onload=`
- `alert()`
- etc.
