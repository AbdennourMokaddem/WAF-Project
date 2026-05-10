# Phase 4 — Tests & Analyse Comparative

## Objectif

Comparer les 3 setups avec des données chiffrées :
1. DVWA **sans protection**
2. DVWA + **WAF Open-Source** (ModSecurity)
3. DVWA + **Custom WAF** (Python)

## Prérequis

| Service | Port | Commande |
|---------|------|----------|
| DVWA (sans WAF) | 8080 | `cd phase1-target && docker compose up -d` |
| ModSecurity WAF | 80 | `cd phase2-opensource-waf && docker compose up -d` |
| Custom WAF | 8888 | `cd phase3-custom-waf && docker compose up -d` |

## Lancer tous les tests

```bash
cd phase4-testing/scripts
bash run_all_tests.sh
```

## Résultats

| Métrique | Sans WAF | WAF Open-Source | Custom WAF |
|----------|----------|----------------|------------|
| Requêtes bloquées | 0 | 1394 | 100% (10/10 tests) |
| SQLi bloquées | 0% | 100% | 100% |
| XSS bloquées | 0% | 100% | 100% |
| LFI bloquées | 0% | - | 100% |
| CMDi bloquées | 0% | - | 100% |
| Faux positifs | - | 0 | 0 |

## Scanner avec OWASP ZAP

```bash
# Lancer ZAP
zaproxy &

# Scanner sans WAF
# URL : http://localhost:8080

# Scanner avec WAF open-source
# URL : http://localhost

# Scanner avec Custom WAF
# URL : http://localhost:8888
```

Générer les rapports : `Report → Generate Report → HTML`
