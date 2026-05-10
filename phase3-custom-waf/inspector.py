"""
inspector.py — Moteur d'inspection des requêtes HTTP
Confronte les données normalisées aux règles de sécurité.
"""
from dataclasses import dataclass, field
from typing import Optional, List
from rules import ALL_RULES
from normalizer import normalize, normalize_dict, normalize_headers


@dataclass
class DetectionResult:
    """Résultat d'une inspection WAF."""
    blocked: bool
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    severity: Optional[str] = None
    zone: Optional[str] = None
    payload: Optional[str] = None
    all_matches: List[dict] = field(default_factory=list)


class Inspector:
    """
    Moteur d'inspection principal.
    Analyse toutes les zones de la requête HTTP selon les règles configurées.
    """

    def __init__(self, rules=None):
        self.rules = rules if rules is not None else ALL_RULES

    def inspect(self,
                uri: str = "",
                headers: dict = None,
                args: dict = None,
                body: dict = None,
                raw_body: str = "",
                cookies: dict = None) -> DetectionResult:
        """
        Inspecte tous les éléments de la requête.
        Retourne le premier match critique, ou le premier match trouvé.
        """
        headers  = headers  or {}
        args     = args     or {}
        body     = body     or {}
        cookies  = cookies  or {}

        # Normalisation de toutes les zones
        zones = {
            "uri":     normalize(uri),
            "headers": self._flatten_dict(normalize_headers(headers)),
            "args":    self._flatten_dict(normalize_dict(args)),
            "body":    self._flatten_dict(normalize_dict(body)) + " " + normalize(raw_body),
            "cookies": self._flatten_dict(normalize_dict(cookies)),
        }

        all_matches = []

        for rule in self.rules:
            for zone_name in rule.zones:
                zone_value = zones.get(zone_name, "")
                match = rule.pattern.search(zone_value)
                if match:
                    all_matches.append({
                        "rule_id":     rule.id,
                        "description": rule.description,
                        "severity":    rule.severity,
                        "zone":        zone_name,
                        "payload":     match.group(0),
                    })

        if not all_matches:
            return DetectionResult(blocked=False)

        # Prioriser les CRITICAL, puis HIGH
        priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_matches.sort(key=lambda m: priority.get(m["severity"], 99))
        top = all_matches[0]

        return DetectionResult(
            blocked=True,
            rule_id=top["rule_id"],
            rule_description=top["description"],
            severity=top["severity"],
            zone=top["zone"],
            payload=top["payload"],
            all_matches=all_matches,
        )

    @staticmethod
    def _flatten_dict(d: dict) -> str:
        """Transforme un dict en chaîne plate pour le pattern matching."""
        return " ".join(str(v) for v in d.values())
