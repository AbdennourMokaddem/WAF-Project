"""
rules/xss.py — Signatures de détection Cross-Site Scripting (XSS)
"""
import re
from rules.sqli import Rule
from typing import List


XSS_RULES: List[Rule] = [

    Rule(
        id="XSS-001",
        description="XSS - Balise <script> (reflected/stored)",
        pattern=re.compile(
            r"<\s*script[\s>]",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "headers", "cookies"],
        severity="CRITICAL",
    ),

    Rule(
        id="XSS-002",
        description="XSS - Gestionnaires d'événements HTML (on*=)",
        pattern=re.compile(
            r"\bon\w+\s*=",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "headers", "cookies"],
        severity="CRITICAL",
    ),

    Rule(
        id="XSS-003",
        description="XSS - Pseudo-protocole javascript:",
        pattern=re.compile(
            r"javascript\s*:",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "headers", "cookies"],
        severity="CRITICAL",
    ),

    Rule(
        id="XSS-004",
        description="XSS - Balises dangereuses (img, iframe, object, embed, svg)",
        pattern=re.compile(
            r"<\s*(img|iframe|object|embed|svg|form|input|link|meta|base)\b[^>]*(src|href|action|xlink:href)\s*=",
            re.IGNORECASE | re.DOTALL
        ),
        zones=["args", "body", "uri", "cookies"],
        severity="HIGH",
    ),

    Rule(
        id="XSS-007",
        description="XSS - eval() et fonctions JS d'exécution",
        pattern=re.compile(
            r"\b(eval|setTimeout|setInterval|Function|alert|confirm|prompt)\s*\(",
            re.IGNORECASE
        ),
        zones=["args", "body", "uri", "cookies"],
        severity="HIGH",
    ),
]
