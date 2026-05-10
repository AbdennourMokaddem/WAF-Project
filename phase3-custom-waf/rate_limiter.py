"""
rate_limiter.py — Rate Limiting en mémoire (anti brute-force / DDoS)
"""
import time
from collections import defaultdict
from threading import Lock
import config


class RateLimiter:
    """
    Implémentation sliding-window rate limiter en mémoire.
    Stocke les timestamps de requêtes par IP.
    """

    def __init__(self):
        self._requests: dict = defaultdict(list)  # IP → [timestamps]
        self._banned:   dict = {}                 # IP → ban_expiry_timestamp
        self._lock = Lock()

    def check(self, ip: str) -> tuple[bool, str]:
        """
        Vérifie si l'IP est rate-limitée.
        Retourne (is_allowed, reason)
        """
        if not config.RATE_LIMIT_ENABLED:
            return True, ""

        # IP whitelistée ?
        if ip in config.IP_WHITELIST:
            return True, ""

        # IP blacklistée ?
        if ip in config.IP_BLACKLIST:
            return False, "IP_BLACKLISTED"

        now = time.time()

        with self._lock:
            # Vérifier si bannie
            if ip in self._banned:
                if now < self._banned[ip]:
                    remaining = int(self._banned[ip] - now)
                    return False, f"BANNED (encore {remaining}s)"
                else:
                    del self._banned[ip]

            # Nettoyage sliding window
            window_start = now - config.RATE_LIMIT_WINDOW
            self._requests[ip] = [t for t in self._requests[ip] if t > window_start]

            # Enregistrer la requête actuelle
            self._requests[ip].append(now)

            # Vérifier le seuil
            count = len(self._requests[ip])
            if count > config.RATE_LIMIT_MAX_REQ:
                # Bannir l'IP
                self._banned[ip] = now + config.RATE_LIMIT_BAN_TTL
                self._requests[ip].clear()
                return False, f"RATE_LIMITED ({count} req/{config.RATE_LIMIT_WINDOW}s)"

        return True, ""

    def get_stats(self, ip: str) -> dict:
        """Retourne les statistiques de rate pour une IP."""
        now = time.time()
        with self._lock:
            window_start = now - config.RATE_LIMIT_WINDOW
            recent = [t for t in self._requests.get(ip, []) if t > window_start]
            banned_until = self._banned.get(ip, 0)
            return {
                "ip": ip,
                "requests_in_window": len(recent),
                "is_banned": now < banned_until,
                "ban_expires": banned_until if now < banned_until else None,
            }


# Instance globale
rate_limiter = RateLimiter()
