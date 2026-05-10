"""
logger.py — Journalisation JSON structurée pour le WAF
"""
import json
import os
import asyncio
from datetime import datetime, timezone
from typing import Optional
import aiofiles
import config

# Couleurs console
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORAMA = True
except ImportError:
    COLORAMA = False


class WafLogger:
    """Logger asynchrone qui écrit des événements WAF en JSON sur disque."""

    def __init__(self, log_file: str = None):
        self.log_file = log_file or config.LOG_FILE
        # Créer le dossier parent si nécessaire
        os.makedirs(os.path.dirname(self.log_file) if os.path.dirname(self.log_file) else ".", exist_ok=True)

    async def log_blocked(self,
                          client_ip: str,
                          method: str,
                          uri: str,
                          rule_id: str,
                          rule_description: str,
                          severity: str,
                          zone: str,
                          payload: str,
                          all_matches: list = None):
        """Journalise une requête bloquée."""
        event = {
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "event_type":       "BLOCKED",
            "client_ip":        client_ip,
            "http_method":      method,
            "uri":              uri,
            "waf_rule_id":      rule_id,
            "rule_description": rule_description,
            "severity":         severity,
            "zone_matched":     zone,
            "malicious_payload": payload,
            "all_matches":      all_matches or [],
        }
        await self._write(event)
        self._console_blocked(event)

    async def log_allowed(self, client_ip: str, method: str, uri: str):
        """Journalise une requête autorisée (debug mode)."""
        event = {
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "event_type":  "ALLOWED",
            "client_ip":   client_ip,
            "http_method": method,
            "uri":         uri,
        }
        # Log console uniquement (pas de fichier pour les req normales)
        if config.LOG_CONSOLE:
            self._console_allowed(event)

    async def log_rate_limited(self, client_ip: str, uri: str):
        """Journalise un bannissement par rate limiting."""
        event = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "event_type": "RATE_LIMITED",
            "client_ip":  client_ip,
            "uri":        uri,
        }
        await self._write(event)
        if config.LOG_CONSOLE:
            print(f"[RATE-LIMIT] {client_ip} → {uri}")

    async def _write(self, event: dict):
        """Écriture asynchrone dans le fichier de log JSON (une ligne par événement)."""
        line = json.dumps(event, ensure_ascii=False) + "\n"
        async with aiofiles.open(self.log_file, "a", encoding="utf-8") as f:
            await f.write(line)

    def _console_blocked(self, event: dict):
        if not config.LOG_CONSOLE:
            return
        severity_colors = {
            "CRITICAL": Fore.RED    if COLORAMA else "",
            "HIGH":     Fore.YELLOW if COLORAMA else "",
            "MEDIUM":   Fore.CYAN   if COLORAMA else "",
            "LOW":      Fore.WHITE  if COLORAMA else "",
        } if COLORAMA else {}

        color = severity_colors.get(event.get("severity", ""), "")
        reset = Style.RESET_ALL if COLORAMA else ""
        ts    = event["timestamp"][11:19]   # HH:MM:SS

        print(
            f"{color}[{ts}] 🚫 BLOCKED"
            f" | {event['client_ip']}"
            f" | {event['waf_rule_id']} ({event['severity']})"
            f" | zone={event['zone_matched']}"
            f" | payload={repr(event['malicious_payload'][:80])}"
            f"{reset}"
        )

    def _console_allowed(self, event: dict):
        color = Fore.GREEN if COLORAMA else ""
        reset = Style.RESET_ALL if COLORAMA else ""
        ts    = event["timestamp"][11:19]
        print(f"{color}[{ts}] ✅ ALLOWED | {event['client_ip']} | {event['http_method']} {event['uri']}{reset}")


# Instance globale
logger = WafLogger()
