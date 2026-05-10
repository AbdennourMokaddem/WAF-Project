"""
rules/__init__.py — Agrégation de toutes les règles WAF
"""
from rules.sqli import SQLI_RULES
from rules.xss import XSS_RULES
from rules.lfi_cmdi import LFI_RULES, CMDI_RULES

ALL_RULES = SQLI_RULES + XSS_RULES + LFI_RULES + CMDI_RULES

__all__ = ["ALL_RULES", "SQLI_RULES", "XSS_RULES", "LFI_RULES", "CMDI_RULES"]
