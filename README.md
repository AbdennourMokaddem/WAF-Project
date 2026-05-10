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

ABDENNOUR MOKADDEM 
BILAL BAHIJ

---

## 📁 Structure du repo

```
WAF-Project/
├── phase1-target/              → App vulnérable (DVWA)
├── phase2-opensource-waf/      → ModSecurity + OWASP CRS
│   ├── docker-compose.yml
│   ├── modsecurity/            → Configs ModSecurity
│   ├── scripts/                → Scripts de test
│   └── reports/                → Rapports ZAP
├── phase3-custom-waf/          → Custom WAF Python
│   ├── waf.py
│   ├── rules/                  → Règles de détection
│   └── logs/                   → Logs des attaques bloquées
└── phase4-testing/             → Scripts de test comparatifs
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

Accéder à DVWA via le WAF :
```
http://localhost
```

---

## 📊 Résultats Phase 4 — Comparaison

| Métrique | Sans WAF | WAF Open-Source | Custom WAF |
|----------|----------|----------------|------------|
| Requêtes bloquées | 0 | 1394 (23.6%) | - |
| SQLi bloquées | 0% | 100% | - |
| XSS bloquées | 0% | 100% | - |
| Alertes ZAP High | 0 | 0 | - |
| Alertes ZAP Medium | 3 | 3 | - |
| Faux positifs critiques | - | 0 | - |

---

## 📄 Rapport final

Le rapport complet est disponible dans : `rapport/rapport_final.pdf`
