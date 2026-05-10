#!/bin/bash
# ================================================
# Script de test — Cross-Site Scripting (XSS)
# Auteur : Abdennour
# Usage  : bash test_xss.sh [URL]
# ================================================

TARGET="${1:-http://localhost}"
COOKIE="security=low; PHPSESSID=REMPLACER_PAR_VOTRE_SESSION"

echo "=========================================="
echo "  TEST XSS — WAF ModSecurity"
echo "  Cible : $TARGET"
echo "=========================================="

payloads=(
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
    "<SCRIPT>alert('XSS')</SCRIPT>"
    "<body onload=alert(1)>"
    "<iframe src=javascript:alert(1)>"
    "<script>document.cookie</script>"
)

echo ""
echo "[*] XSS Reflected — /vulnerabilities/xss_r/"
echo "------------------------------------------"
BLOCKED=0
PASSED=0

for payload in "${payloads[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -G "${TARGET}/vulnerabilities/xss_r/" \
        --data-urlencode "name=${payload}" \
        -b "${COOKIE}" \
        --max-time 10)

    if [ "$response" == "403" ]; then
        printf "✅ BLOQUÉ (%s) → %s\n" "$response" "${payload:0:50}"
        ((BLOCKED++))
    else
        printf "❌ PASSÉ  (%s) → %s\n" "$response" "${payload:0:50}"
        ((PASSED++))
    fi
done

echo ""
echo "[*] XSS DOM — /vulnerabilities/xss_d/"
echo "------------------------------------------"
BLOCKED_DOM=0
PASSED_DOM=0

for payload in "${payloads[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -G "${TARGET}/vulnerabilities/xss_d/" \
        --data-urlencode "default=${payload}" \
        -b "${COOKIE}" \
        --max-time 10)

    if [ "$response" == "403" ]; then
        printf "✅ BLOQUÉ (%s) → %s\n" "$response" "${payload:0:50}"
        ((BLOCKED_DOM++))
    else
        printf "❌ PASSÉ  (%s) → %s\n" "$response" "${payload:0:50}"
        ((PASSED_DOM++))
    fi
done

echo ""
echo "=========================================="
echo "  RÉSULTATS"
echo "------------------------------------------"
echo "  XSS Reflected : $BLOCKED bloquées / ${#payloads[@]}"
echo "  XSS DOM       : $BLOCKED_DOM bloquées / ${#payloads[@]}"
TOTAL_BLOCKED=$((BLOCKED + BLOCKED_DOM))
TOTAL=$((${#payloads[@]} * 2))
RATE=$(echo "scale=1; $TOTAL_BLOCKED * 100 / $TOTAL" | bc)
echo "  📊 Taux global : ${RATE}%"
echo "=========================================="
