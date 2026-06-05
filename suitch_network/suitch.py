#!/usr/bin/env python3
"""
Suitch Network — DIAGNÓSTICO: buscar en app.js el endpoint de CSRF
"""

import re, ssl, urllib.request, urllib.parse, http.cookiejar, gzip as gz, logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger()

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
BASE = "https://suitch.network"


def fetch(url):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip"})
    with opener.open(req, timeout=30) as r:
        raw = r.read()
        if r.headers.get("Content-Encoding") == "gzip":
            raw = gz.decompress(raw)
        return raw.decode("utf-8", errors="replace")


def main():
    # 1. Obtener el nombre del app.js desde la página principal
    log.info("Obteniendo nombre del app.js...")
    index = fetch(f"{BASE}/")
    m = re.search(r'src="(/js/app\.[^"]+\.js)"', index)
    if not m:
        log.error("No se encontró app.js en el HTML")
        return
    app_js_path = m.group(1)
    log.info("app.js: %s", app_js_path)

    # 2. Descargar app.js
    log.info("Descargando app.js...")
    js = fetch(f"{BASE}{app_js_path}")
    log.info("app.js tamaño: %d bytes", len(js))

    # 3. Buscar patrones de CSRF/token en el JS
    patterns = [
        r'csrf[_\-]?token',
        r'authenticity_token',
        r'/auth/[^\s"\']+',
        r'cookie\.json',
        r'token["\s]*:["\s]*function',
        r'getToken\|fetchToken\|loadToken',
        r'"token"[^,]{0,50}header',
    ]
    log.info("=== Buscando patrones en app.js ===")
    for pat in patterns:
        matches = re.findall(pat, js, re.IGNORECASE)
        if matches:
            log.info("Patrón [%s]: %s", pat, list(set(matches))[:5])

    # 4. Buscar URLs de API en el JS (rutas que empiezan con /auth o /api)
    api_routes = re.findall(r'["\']/(auth|api|users)[^"\']{2,50}["\']', js)
    unique_routes = list(set(api_routes))
    log.info("=== Rutas de API encontradas en app.js ===")
    for r in sorted(unique_routes):
        log.info("  %s", r)

    # 5. Guardar fragmento alrededor de "csrf" si existe
    idx = js.lower().find("csrf")
    if idx >= 0:
        log.info("=== Contexto alrededor de 'csrf' (pos %d) ===", idx)
        log.info("%s", js[max(0,idx-200):idx+300])
    else:
        idx2 = js.lower().find("token")
        if idx2 >= 0:
            log.info("=== Contexto alrededor de 'token' (pos %d) ===", idx2)
            log.info("%s", js[max(0,idx2-200):idx2+300])

    log.info("=== FIN diagnóstico app.js ===")


if __name__ == "__main__":
    main()
