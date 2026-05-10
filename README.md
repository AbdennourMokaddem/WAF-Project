# WAF Project — Under the Hood

> **ENSAM Casablanca — Cybersécurité**  

## 🎯 Objectif

Ce projet explore le fonctionnement interne des Web Application Firewalls (WAF) à travers trois approches :

1. **Phase 1** — Déploiement d'une application vulnérable (DVWA)
2. **Phase 2** — WAF Open-Source (ModSecurity + OWASP CRS)
3. **Phase 3** — Custom WAF from scratch (Python)
4. **Phase 4** — Tests & Analyse comparative

---

## 👥 Membres du groupe

- **Abdennour Mokaddem**
- **Bilal Bahij**

---

## 📁 Structure du repo

```text
WAF-Project/
├── phase1-target/              → App vulnérable (DVWA)
├── phase2-opensource-waf/      → ModSecurity + OWASP CRS
│   ├── docker-compose.yml
│   └── modsecurity/            → Configs ModSecurity
├── phase3-custom-waf/          → Advanced Custom WAF (Python/Aiohttp)
│   ├── docker-compose.yml      → Déploiement conteneurisé du WAF
│   ├── Dockerfile              # Image du WAF
│   ├── main.py                 → Async Proxy Engine
│   ├── config.py               → Configuration (Ports, Target, Mode)
│   ├── inspector.py            → Rule Engine
│   ├── normalizer.py           → Anti-Evasion Pipeline
│   ├── rate_limiter.py         → Protection anti-flood
│   ├── logger.py               → Journalisation asynchrone JSON
│   ├── requirements.txt        → Dépendances Python (aiohttp, etc.)
│   ├── rules/                  → Signatures de détection (SQLi, XSS, LFI)
│   ├── logs/                   → Fichiers de logs générés
│   ├── block_page.html         → Interface 403 personnalisée
│   └── waf.py                  → (Ancien script - Obsolète)
└── phase4-testing/             → Scripts de test comparatifs
    └── scripts/
        ├── run_all_tests.sh    → Lanceur de tests global
        └── waf_comparison.py   → Générateur de tableau comparatif (Python)
```

---

## 🚀 Démarrage rapide

### Prérequis
- Docker + Docker Compose
- Python 3.10+
- OWASP ZAP 2.17+

### Lancer l'environnement complet

```bash
git clone https://github.com/[votre-username]/WAF-Project.git
cd WAF-Project/phase2-opensource-waf
docker compose up -d
```

Accéder à DVWA via le WAF Open-Source (Port 80) :
```
http://localhost
```

Accéder à DVWA via le Custom WAF (Port 8888) :
```bash
cd ../phase3-custom-waf
docker compose up -d
# Accès : http://localhost:8888
```

---

## 📊 Résultats Phase 4 — Comparaison

| Métrique | Sans WAF | WAF Open-Source | Custom WAF |
|----------|----------|----------------|------------|
| Requêtes bloquées | 0 | 1394 (23.6%) | 100% (10/10 tests) |
| SQLi bloquées | 0% | 100% | 100% |
| XSS bloquées | 0% | 100% | 100% |
| LFI bloquées | 0% | - | 100% |
| CMDi bloquées | 0% | - | 100% |
| Faux positifs critiques | - | 0 | 0 |

---

## 📄 Rapport final

Le rapport complet est disponible dans : `rapport/rapport_final.pdf`
