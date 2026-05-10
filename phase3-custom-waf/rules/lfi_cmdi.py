"""
rules/lfi.py — Signatures LFI / Path Traversal
rules/cmdi.py — Signatures Command Injection
"""
import re
from rules.sqli import Rule
from typing import List


# ─── LFI / Path Traversal ────────────────────────────────────────────────────

LFI_RULES: List[Rule] = [

    Rule(
        id="LFI-001",
        description="LFI - Séquences de traversal de répertoire (../)",
        pattern=re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)",
            re.IGNORECASE
        ),
        zones=["uri", "args", "body", "headers"],
        severity="CRITICAL",
    ),

    Rule(
        id="LFI-002",
        description="LFI - Accès à des fichiers système sensibles",
        pattern=re.compile(
            r"(etc/passwd|etc/shadow|etc/hosts|proc/self|windows/system32|win\.ini|boot\.ini)",
            re.IGNORECASE
        ),
        zones=["uri", "args", "body"],
        severity="CRITICAL",
    ),

    Rule(
        id="LFI-003",
        description="LFI - PHP wrappers (php://input, php://filter, file://)",
        pattern=re.compile(
            r"(php://|file://|glob://|zip://|data://text/plain)",
            re.IGNORECASE
        ),
        zones=["uri", "args", "body"],
        severity="HIGH",
    ),

    Rule(
        id="LFI-004",
        description="LFI - Log poisoning targets",
        pattern=re.compile(
            r"(var/log|proc/self/environ|/apache/logs|/nginx/logs)",
            re.IGNORECASE
        ),
        zones=["uri", "args", "body"],
        severity="HIGH",
    ),
]


# ─── Command Injection ────────────────────────────────────────────────────────

CMDI_RULES: List[Rule] = [

    Rule(
        id="CMDI-001",
        description="CMDi - Séparateurs de commandes shell",
        pattern=re.compile(
            r"[;|&`$]\s*(ls|cat|id|whoami|uname|pwd|wget|curl|bash|sh|python|perl|ruby|nc|netcat|ncat)",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "headers"],
        severity="CRITICAL",
    ),

    Rule(
        id="CMDI-002",
        description="CMDi - Substitution de commande (backtick / $())",
        pattern=re.compile(
            r"(`[^`]+`|\$\([^)]+\))",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri"],
        severity="CRITICAL",
    ),

    Rule(
        id="CMDI-003",
        description="CMDi - Commandes Windows dangereuses",
        pattern=re.compile(
            r"\b(cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32)\b",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "headers"],
        severity="CRITICAL",
    ),

    Rule(
        id="CMDI-004",
        description="CMDi - Redirection et exfiltration",
        pattern=re.compile(
            r"(wget|curl)\s+http",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri"],
        severity="HIGH",
    ),

    Rule(
        id="CMDI-005",
        description="CMDi - Reverse shell patterns",
        pattern=re.compile(
            r"(bash\s+-i|/dev/tcp|/dev/udp|nc\s+-e|ncat\s+-e)",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "headers"],
        severity="CRITICAL",
    ),
]
