# Phase 1 — Application Vulnérable (DVWA)

## Objectif
Prouver que DVWA est vulnérable **avant** la mise en place du WAF.

## Démarrage

```bash
docker compose up -d
```

Accéder à : `http://localhost:8080/setup.php`

1. Cliquer **"Create / Reset Database"**
2. Login : `admin` / `password`
3. DVWA Security → mettre sur **"Low"**

---

## Attaques testées

### SQL Injection
- URL : `http://localhost:8080/vulnerabilities/sqli/`
- Payload : `1 OR 1=1`
- Résultat : tous les utilisateurs affichés ✅

### XSS Reflected
- URL : `http://localhost:8080/vulnerabilities/xss_r/`
- Payload : `<script>alert('XSS')</script>`
- Résultat : popup alert exécutée ✅

### XSS DOM
- URL : `http://localhost:8080/vulnerabilities/xss_d/?default=<script>alert('XSS')</script>`
- Résultat : popup alert exécutée ✅

---

## ⚠️ Important
Ce setup est **temporaire** pour la Phase 1 uniquement.  
En production, utiliser Phase 2 (WAF) pour protéger l'application.
