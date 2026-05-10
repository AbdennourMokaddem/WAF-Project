# Phase 3 — Advanced Custom WAF (Python)

Ce module implémente un Web Application Firewall (WAF) personnalisé ultra-performant écrit en Python asynchrone (`aiohttp`).

## 🛡️ Fonctionnalités Avancées

| Fonctionnalité | Description | Statut |
|----------------|-------------|--------|
| **Async Proxy** | Moteur de reverse proxy haute performance basé sur `aiohttp`. | ✅ |
| **Normalisation** | Pipeline anti-évasion (décodage URL récursif, suppression commentaires SQL, collapse whitespace). | ✅ |
| **Inspection Multi-Zone** | Analyse URI, Headers, Cookies, et Body (JSON & Form-data). | ✅ |
| **Moteur de Règles** | Système modulaire de signatures (Regex) classées par sévérité. | ✅ |
| **Rate Limiting** | Protection anti-brute-force avec sliding window et bannissement temporaire. | ✅ |
| **Logging JSON** | Journalisation structurée compatible avec les outils SIEM (ELK, Splunk). | ✅ |
| **Page 403 Premium** | Interface utilisateur moderne pour les requêtes bloquées. | ✅ |

## 📁 Structure du Module

```text
phase3-custom-waf/
├── docker-compose.yml  # Déploiement conteneurisé
├── Dockerfile          # Image du WAF
├── requirements.txt    # Dépendances Python
├── main.py             # Point d'entrée & Moteur Proxy
├── inspector.py        # Logique d'inspection
├── normalizer.py       # Pipeline anti-obfuscation
├── config.py           # Configuration (Ports, Target, Mode)
├── logger.py           # Journalisation asynchrone
├── rate_limiter.py     # Protection anti-flood
├── rules/              # Signatures de détection (SQLi, XSS, LFI)
├── logs/               # Fichiers de logs JSON
├── block_page.html     # Page d'erreur 403 personnalisée
└── waf.py              # (Ancien script - Obsolète)
```

## 🚀 Démarrage

### 🐳 Docker (Recommandé)

1. Assurez-vous que l'application cible (Phase 1) est lancée sur le port `8080`.
2. Lancez le WAF :
   ```bash
   docker compose up -d
   ```
3. Accédez à l'application protégée via le WAF :
   ```
   http://localhost:8888
   ```

## 📊 Analyse des Menaces

Les alertes sont stockées dans `logs/waf_alerts.json` au format JSON. Chaque entrée contient :
- L'IP de l'attaquant
- Le payload malveillant détecté
- La zone touchée (URI, Body, Header, etc.)
- La sévérité (CRITICAL, HIGH, etc.)
- L'ID de la règle déclenchée
