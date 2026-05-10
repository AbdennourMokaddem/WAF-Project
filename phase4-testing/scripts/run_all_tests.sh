#!/bin/bash
# ================================================
# Script Phase 4 — Comparaison des 3 setups
# Auteur : Abdennour + [Ami]
# Usage  : bash run_all_tests.sh
# ================================================

REPORTS_DIR="../phase2-opensource-waf/reports"
mkdir -p "$REPORTS_DIR"

echo "=========================================="
echo "  PHASE 4 — TESTS COMPARATIFS"
echo "=========================================="

echo ""
echo "⚠️  Avant de lancer ce script :"
echo "   1. DVWA doit tourner sur port 8080 (Phase 1)"
echo "   2. ModSecurity WAF sur port 80 (Phase 2)"
echo "   3. Custom WAF sur port 8888 (Phase 3)"
echo ""
read -p "Appuyer sur Entrée pour continuer..."

# ================================================
# TEST 1 — Sans WAF (DVWA direct)
# ================================================
echo ""
echo "[1/3] Test SANS WAF — http://localhost:8080"
echo "------------------------------------------"

if curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 | grep -q "200\|302"; then
    echo "✅ DVWA accessible sur port 8080"

    cd ../phase2-opensource-waf/scripts
    bash test_sqli.sh http://localhost:8080 > "$REPORTS_DIR/sqli_sans_waf.txt" 2>&1
    bash test_xss.sh http://localhost:8080 > "$REPORTS_DIR/xss_sans_waf.txt" 2>&1
    cd ../../phase4-testing/scripts

    echo "✅ Tests SQLi et XSS sans WAF terminés"
    echo "   Résultats : $REPORTS_DIR/sqli_sans_waf.txt"
else
    echo "❌ DVWA inaccessible sur port 8080"
    echo "   Lancer : cd phase1-target && docker compose up -d"
fi

# ================================================
# TEST 2 — Avec WAF Open-Source (ModSecurity)
# ================================================
echo ""
echo "[2/3] Test AVEC WAF Open-Source — http://localhost"
echo "------------------------------------------"

if curl -s -o /dev/null -w "%{http_code}" http://localhost | grep -q "200\|302"; then
    echo "✅ ModSecurity WAF accessible sur port 80"

    cd ../phase2-opensource-waf/scripts
    bash test_sqli.sh http://localhost > "$REPORTS_DIR/sqli_avec_waf_opensource.txt" 2>&1
    bash test_xss.sh http://localhost > "$REPORTS_DIR/xss_avec_waf_opensource.txt" 2>&1
    bash compare.sh > "$REPORTS_DIR/comparaison_logs.txt" 2>&1
    cd ../../phase4-testing/scripts

    echo "✅ Tests WAF open-source terminés"
    echo "   Résultats : $REPORTS_DIR/"
else
    echo "❌ ModSecurity WAF inaccessible sur port 80"
    echo "   Lancer : cd phase2-opensource-waf && docker compose up -d"
fi

# ================================================
# TEST 3 — Avec Custom WAF (Python)
# ================================================
echo ""
echo "[3/3] Test AVEC Custom WAF — http://localhost:8888"
echo "------------------------------------------"

if curl -s -o /dev/null -w "%{http_code}" http://localhost:8888 | grep -q "200\|302\|403"; then
    echo "✅ Custom WAF accessible sur port 8888"

    cd ../phase2-opensource-waf/scripts
    bash test_sqli.sh http://localhost:8888 > "$REPORTS_DIR/sqli_avec_custom_waf.txt" 2>&1
    bash test_xss.sh http://localhost:8888 > "$REPORTS_DIR/xss_avec_custom_waf.txt" 2>&1
    cd ../../phase4-testing/scripts

    echo "✅ Tests Custom WAF terminés"
else
    echo "❌ Custom WAF inaccessible sur port 8888"
    echo "   Lancer : cd phase3-custom-waf && python3 waf.py"
fi

# ================================================
# RÉSUMÉ FINAL
# ================================================
echo ""
echo "=========================================="
echo "  RÉSUMÉ DES FICHIERS GÉNÉRÉS"
echo "=========================================="
ls -la "$REPORTS_DIR/"
echo ""
echo "✅ Phase 4 terminée !"
echo "   Ouvrir les rapports : firefox $REPORTS_DIR/*.html"
