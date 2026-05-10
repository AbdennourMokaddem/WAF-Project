"""
normalizer.py — Normalisation des données HTTP avant inspection
C'est l'étape la plus critique pour contrer l'évasion/obfuscation.
"""
import re
from urllib.parse import unquote, unquote_plus


def normalize(value: str) -> str:
    """
    Pipeline complet de normalisation :
    1. Double décodage URL (contre double URL-encoding : %2527 → %27 → ')
    2. Mise en minuscules
    3. Suppression des commentaires SQL  (/* ... */ et -- ...)
    4. Collapse des espaces/tabulations/newlines
    5. Suppression des caractères nuls
    """
    if not isinstance(value, str):
        return str(value)

    # 1. Double URL-decode (prévention double-évasion)
    decoded = unquote(unquote_plus(value))

    # 2. Lowercase
    decoded = decoded.lower()

    # 3. Supprimer les commentaires SQL : /* ... */ sur une ou plusieurs lignes
    decoded = re.sub(r'/\*.*?\*/', ' ', decoded, flags=re.DOTALL)

    # 4. Supprimer les commentaires SQL de fin de ligne : -- ...
    decoded = re.sub(r'--[^\n]*', ' ', decoded)

    # 5. Supprimer les commentaires MySQL style : # ...
    decoded = re.sub(r'#[^\n]*', ' ', decoded)

    # 6. Collapse whitespace (espaces, tabs, newlines → espace unique)
    decoded = re.sub(r'[\s\x00\x0a\x0d\x09]+', ' ', decoded).strip()

    # 7. Remplacer les encodages hexadécimaux courants
    decoded = re.sub(r'0x[0-9a-f]+', lambda m: _hex_to_str(m.group()), decoded)

    return decoded


def _hex_to_str(hex_val: str) -> str:
    """Convertit 0x414243 → 'abc' (lowercase)"""
    try:
        raw = bytes.fromhex(hex_val[2:])
        return raw.decode('utf-8', errors='replace').lower()
    except Exception:
        return hex_val


def normalize_dict(d: dict) -> dict:
    """Normalise toutes les valeurs d'un dictionnaire de paramètres."""
    result = {}
    for k, v in d.items():
        if isinstance(v, list):
            result[normalize(k)] = [normalize(item) for item in v]
        else:
            result[normalize(k)] = normalize(str(v))
    return result


def normalize_headers(headers: dict) -> dict:
    """Normalise les en-têtes HTTP (clés et valeurs)."""
    return {k.lower(): normalize(v) for k, v in headers.items()}
