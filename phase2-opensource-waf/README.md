# Phase 2 — WAF Open-Source (ModSecurity + OWASP CRS)

**Responsable : Abdennour**

## Architecture

```
Client (Browser / ZAP)
        ↓
ModSecurity + Apache (port 80)   ← WAF + Reverse Proxy
        ↓
DVWA (réseau Docker interne)     ← App protégée
```

DVWA est **inaccessible directement** depuis l'extérieur. Tout le trafic passe obligatoirement par ModSecurity.

---

## Démarrage

```bash
# Lancer l'environnement
docker compose up -d

# Vérifier
docker compose ps -a

# Accéder à DVWA via le WAF
# http://localhost
```

---

## Configuration ModSecurity

| Paramètre | Valeur | Description |
|-----------|--------|-------------|
| `PARANOIA` | 1 | Niveau de strictness (1=standard) |
| `ANOMALY_INBOUND` | 5 | Score max avant blocage requête |
| `ANOMALY_OUTBOUND` | 4 | Score max avant blocage réponse |
| `BACKEND` | http://dvwa:80 | App cible (reverse proxy) |

### Fichier d'exclusions

`modsecurity/RESPONSE-999-EXCLUSIONS.conf` contient les exclusions pour éviter les faux positifs sur DVWA :
- Champ `password` du login (mot de passe complexe détecté comme SQLi)
- Champ `username` du login

---

## Scripts de test

```bash
cd scripts/

# Tester les protections SQLi
bash test_sqli.sh http://localhost

# Tester les protections XSS
bash test_xss.sh http://localhost

# Analyser les logs et générer le tableau comparatif
bash compare.sh
```

---

## Résultats obtenus

| Métrique | Valeur |
|----------|--------|
| Total requêtes analysées | 5895 |
| Requêtes bloquées (403) | 1394 (23.6%) |
| Requêtes légitimes (200) | 2637 |
| SQLi bloquées | 100% |
| XSS bloquées | 100% |
| Faux positifs critiques | 0 |

---

## Logs

```bash
# Voir les requêtes bloquées en temps réel
tail -f logs/access.log | grep "403"

# Voir les logs ModSecurity détaillés
docker logs modsecurity-waf -f

# Sauvegarder les logs ModSecurity
docker logs modsecurity-waf > logs/modsec_audit.log 2>&1
```

---

## Arrêter l'environnement

```bash
docker compose down      # Arrêter (données DB conservées)
docker compose down -v   # Arrêter + supprimer volumes
```
