"""
rules/sqli.py — Signatures de détection SQL Injection
Basé sur OWASP CRS et les techniques vues en CTF.
"""
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    zones: List[str]   # 'args', 'body', 'uri', 'headers', 'cookies'
    severity: str      # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'


# ─── Règles SQLi ─────────────────────────────────────────────────────────────

SQLI_RULES: List[Rule] = [

    Rule(
        id="SQLI-001",
        description="SQLi - Opérateur OR/AND classique (1=1, 1=2...)",
        pattern=re.compile(
            r"(\b(or|and)\b\s+[\w'\"]+\s*=\s*[\w'\"]+)"
            r"|(\b(or|and)\b\s+\d+\s*=\s*\d+)",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "cookies"],
        severity="CRITICAL",
    ),

    Rule(
        id="SQLI-002",
        description="SQLi - UNION SELECT (extraction de données)",
        pattern=re.compile(
            r"\bunion\b.{0,20}\bselect\b",
            re.IGNORECASE | re.DOTALL
        ),
        zones=["args", "body", "uri", "cookies"],
        severity="CRITICAL",
    ),

    Rule(
        id="SQLI-003",
        description="SQLi - Mots-clés DDL/DML dangereux",
        pattern=re.compile(
            r"\b(drop|truncate|delete|insert|update|replace|exec|execute|xp_|sp_)\b",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "cookies"],
        severity="HIGH",
    ),

    Rule(
        id="SQLI-004",
        description="SQLi - Fonctions de time-based blind (SLEEP, BENCHMARK, WAITFOR)",
        pattern=re.compile(
            r"\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "cookies"],
        severity="CRITICAL",
    ),

    Rule(
        id="SQLI-005",
        description="SQLi - Caractères d'injection classiques avec contexte SQL",
        pattern=re.compile(
            r"(\'|\"|`)\s*(;|--|\||or|and|union|select|from|where)",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "cookies"],
        severity="HIGH",
    ),

    Rule(
        id="SQLI-006",
        description="SQLi - Commentaires SQL inline utilisés pour bypass",
        pattern=re.compile(
            r"(/\*.*?\*/|--\s*$|;\s*--)",
            re.IGNORECASE | re.DOTALL
        ),
        zones=["args", "body", "uri"],
        severity="MEDIUM",
    ),

    Rule(
        id="SQLI-007",
        description="SQLi - Fonctions d'information système",
        pattern=re.compile(
            r"\b(database|schema|version|user|current_user|system_user|@@version|@@datadir)\s*\(\)",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "cookies"],
        severity="HIGH",
    ),

    Rule(
        id="SQLI-010",
        description="SQLi - Stacked queries (point-virgule)",
        pattern=re.compile(
            r";\s*(select|insert|update|delete|drop|create|alter|exec)",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri"],
        severity="CRITICAL",
    ),
]
