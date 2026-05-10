"""
main.py — Point d'entrée du WAF personnalisé
Reverse proxy HTTP asynchrone avec inspection de sécurité.
"""
import asyncio
import os
import sys
import uuid
import json
from datetime import datetime, timezone
from aiohttp import web, ClientSession, ClientTimeout, TCPConnector

import config
from inspector import Inspector
from logger import logger
from rate_limiter import rate_limiter

# ─── Chargement de la page de blocage ─────────────────────────────────────────
BLOCK_PAGE_PATH = os.path.join(os.path.dirname(__file__), "block_page.html")
with open(BLOCK_PAGE_PATH, "r", encoding="utf-8") as f:
    BLOCK_PAGE_TEMPLATE = f.read()

# ─── Moteur d'inspection ──────────────────────────────────────────────────────
inspector = Inspector()


def get_block_page(rule_id: str, severity: str) -> str:
    """Génère la page 403 avec les détails de l'incident."""
    incident_id = f"WAF-{uuid.uuid4().hex[:8].upper()}"
    timestamp   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (BLOCK_PAGE_TEMPLATE
            .replace("{{RULE_ID}}",     rule_id)
            .replace("{{SEVERITY}}",    severity)
            .replace("{{TIMESTAMP}}",   timestamp)
            .replace("{{INCIDENT_ID}}", incident_id))


def get_client_ip(request: web.Request) -> str:
    """Extrait l'IP réelle du client (supporte X-Forwarded-For)."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote or "unknown"


async def handle_request(request: web.Request) -> web.Response:
    """
    Pipeline principal d'une requête :
    1. Rate limiting
    2. IP whitelist/blacklist
    3. Extraction et normalisation des données HTTP
    4. Inspection WAF
    5. Proxying vers la cible (si safe)
    """
    client_ip = get_client_ip(request)
    method    = request.method
    uri       = request.path_qs

    # ── 1. Rate Limiting ──────────────────────────────────────────────────────
    allowed, reason = rate_limiter.check(client_ip)
    if not allowed:
        await logger.log_rate_limited(client_ip, uri)
        return web.Response(
            status=429,
            content_type="text/html",
            body=get_block_page("RATE-LIMIT", "HIGH").encode()
        )

    # ── 2. Extraction des données HTTP ────────────────────────────────────────
    headers = dict(request.headers)

    # GET params
    args = {}
    for k, v in request.rel_url.query.items():
        args[k] = v

    # POST body
    body_dict = {}
    raw_body  = ""
    try:
        content_type = headers.get("Content-Type", "").lower()
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            post_data = await request.post()
            body_dict = {k: v for k, v in post_data.items()}
        elif "application/json" in content_type:
            raw_body = await request.text()
            try:
                body_dict = json.loads(raw_body)
            except Exception:
                body_dict = {}
        else:
            raw_body = await request.text()
    except Exception:
        pass

    # Cookies
    cookies = {k: v for k, v in request.cookies.items()}

    # ── 3. Inspection WAF ─────────────────────────────────────────────────────
    result = inspector.inspect(
        uri=uri,
        headers=headers,
        args=args,
        body=body_dict,
        raw_body=raw_body,
        cookies=cookies,
    )

    if result.blocked:
        await logger.log_blocked(
            client_ip=client_ip,
            method=method,
            uri=uri,
            rule_id=result.rule_id,
            rule_description=result.rule_description,
            severity=result.severity,
            zone=result.zone,
            payload=result.payload,
            all_matches=result.all_matches,
        )

        if config.WAF_MODE == "block":
            return web.Response(
                status=403,
                content_type="text/html",
                body=get_block_page(result.rule_id, result.severity).encode("utf-8")
            )
        # Mode monitor : on laisse passer mais on a déjà logué
    else:
        await logger.log_allowed(client_ip, method, uri)

    # ── 4. Proxy vers la cible ────────────────────────────────────────────────
    return await proxy_request(request, client_ip, method, uri, headers, raw_body, body_dict)


async def proxy_request(request, client_ip, method, uri, headers, raw_body, body_dict):
    """Transfère la requête vers le serveur cible et retourne la réponse."""
    target_url = config.TARGET_URL.rstrip("/") + request.path_qs

    # Préparer les headers pour le proxy
    proxy_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }
    proxy_headers["X-Forwarded-For"]   = client_ip
    proxy_headers["X-Real-IP"]         = client_ip
    proxy_headers["X-WAF-Inspected"]   = "true"

    connector = TCPConnector(ssl=False)
    timeout   = ClientTimeout(total=30)

    try:
        async with ClientSession(connector=connector, timeout=timeout) as session:
            # Déterminer le body à envoyer
            send_data   = None
            send_json   = None
            send_body   = None
            content_type = headers.get("Content-Type", "").lower()

            if method in ("POST", "PUT", "PATCH"):
                if "application/json" in content_type:
                    send_body = raw_body.encode() if raw_body else b""
                elif body_dict:
                    send_data = body_dict
                else:
                    send_body = raw_body.encode() if raw_body else b""

            async with session.request(
                method=method,
                url=target_url,
                headers=proxy_headers,
                data=send_data,
                json=send_json if send_json else None,
                allow_redirects=False,
            ) as resp:
                # Lire la réponse
                resp_body    = await resp.read()
                resp_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")
                }
                resp_headers["X-Protected-By"] = "Custom-WAF-v1.0"

                return web.Response(
                    status=resp.status,
                    headers=resp_headers,
                    body=resp_body,
                )

    except Exception as e:
        return web.Response(
            status=502,
            text=f"Bad Gateway: {str(e)}",
            content_type="text/plain"
        )


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_route("*", "/{path_info:.*}", handle_request)
    return app


async def main():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║           🛡️  Custom WAF — Reverse Proxy + Inspection         ║
╠══════════════════════════════════════════════════════════════╣
║  Mode    : {mode:<52}║
║  Target  : {target:<52}║
║  Listen  : {listen:<52}║
║  Log     : {log:<52}║
╚══════════════════════════════════════════════════════════════╝
""".format(
        mode   =config.WAF_MODE.upper(),
        target =config.TARGET_URL,
        listen =f"{config.WAF_HOST}:{config.WAF_PORT}",
        log    =config.LOG_FILE,
    )
    print(banner)

    app    = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site   = web.TCPSite(runner, config.WAF_HOST, config.WAF_PORT)
    await site.start()
    print(f"✅ WAF démarré sur http://{config.WAF_HOST}:{config.WAF_PORT}")
    print("   Appuyez sur Ctrl+C pour arrêter.\n")

    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, SystemExit):
        print("\n⛔ Arrêt du WAF...")
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
