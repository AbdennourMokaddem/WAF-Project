#!/bin/bash
# ================================================
# Script de test — SQL Injection
# Auteur : Abdennour
# Usage  : bash test_sqli.sh [URL]
# ================================================

TARGET="${1:-http://localhost}"
COOKIE="security=low; PHPSESSID=REMPLACER_PAR_VOTRE_SESSION"

echo "=========================================="
echo "  TEST SQL INJECTION — WAF ModSecurity"
echo "  Cible : $TARGET"
echo "=========================================="

payloads=(
    "1 OR 1=1"
    "1' OR '1'='1"
    "1' OR 1=1 -- -"
    "' UNION SELECT 1,2,3 -- -"
    "1; DROP TABLE users -- -"
    "1' AND SLEEP(5) -- -"
    "admin'--"
    "1' OR 'x'='x"
)

BLOCKED=0
PASSED=0

echo ""
echo "Payload                          | Status | Résultat"
echo "---------------------------------|--------|----------"

for payload in "${payloads[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -G "${TARGET}/vulnerabilities/sqli/" \
        --data-urlencode "id=${payload}" \
        --data-urlencode "Submit=Submit" \
        -b "${COOKIE}" \
        --max-time 10)

    if [ "$response" == "403" ]; then
        printf "%-32s | %-6s | ✅ BLOQUÉ\n" "${payload:0:32}" "$response"
        ((BLOCKED++))
    elif [ "$response" == "200" ]; then
        printf "%-32s | %-6s | ❌ PASSÉ\n" "${payload:0:32}" "$response"
        ((PASSED++))
    else
        printf "%-32s | %-6s | ⚠️  AUTRE\n" "${payload:0:32}" "$response"
    fi
done

echo ""
echo "=========================================="
echo "  RÉSULTATS"
echo "------------------------------------------"
echo "  ✅ Bloquées : $BLOCKED / ${#payloads[@]}"
echo "  ❌ Passées  : $PASSED / ${#payloads[@]}"
RATE=$(echo "scale=1; $BLOCKED * 100 / ${#payloads[@]}" | bc)
echo "  📊 Taux de blocage : ${RATE}%"
echo "=========================================="
