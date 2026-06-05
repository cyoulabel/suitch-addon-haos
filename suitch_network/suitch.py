#!/usr/bin/env python3
"""Suitch Network — DIAGNÓSTICO: contexto de authenticity_token en app.js"""

import re, ssl, urllib.request, http.cookiejar, gzip as gz, logging, json

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger()

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE
UA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
BASE = "https://suitch.network"


def fetch(url, method="GET", data=None, headers={}):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )
    hdrs = {"User-Agent": UA, "Accept-Encoding": "gzip", "Accept": "application/json,*/*", **headers}
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with opener.open(req, timeout=15) as r:
            raw = r.read()
            if r.headers.get("Content-Encoding") == "gzip": raw = gz.decompress(raw)
            return r.status, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        if e.headers.get("Content-Encoding") == "gzip": raw = gz.decompress(raw)
        return e.code, raw.decode("utf-8", errors="replace")


def main():
    # 1. Bajar app.js
    status, index = fetch(f"{BASE}/")
    m = re.search(r'src="(/js/app\.[^"]+\.js)"', index)
    app_js_path = m.group(1) if m else "/js/app.49dc65c1.js"
    log.info("Bajando %s...", app_js_path)
    status, js = fetch(f"{BASE}{app_js_path}")
    log.info("app.js: %d bytes", len(js))

    # 2. Contexto alrededor de CADA ocurrencia de authenticity_token
    log.info("=== Contextos de authenticity_token ===")
    for m in re.finditer(r'authenticity_token', js):
        start = max(0, m.start() - 300)
        end   = min(len(js), m.end() + 300)
        log.info("--- pos %d ---\n%s", m.start(), js[start:end])

    # 3. Rutas completas de /auth/
    log.info("=== Todas las rutas /auth/ en app.js ===")
    routes = re.findall(r'["\']/(auth/[^"\'?\s]{3,50})["\']', js)
    for r in sorted(set(routes)):
        log.info("  /%s", r)

    # 4. Probar GET /auth/v2/user.json (podría retornar token)
    log.info("=== GET /auth/v2/user.json ===")
    s, b = fetch(f"{BASE}/auth/v2/user.json")
    log.info("Status %s | Body: %s", s, b[:300])

    # 5. Buscar patrón headers con csrf/token en app.js
    log.info("=== Headers con CSRF en app.js ===")
    for m in re.finditer(r'[Xx]-?[Cc][Ss][Rr][Ff]|[Xx]-[Aa]uth', js):
        start = max(0, m.start()-200)
        end   = min(len(js), m.end()+200)
        log.info("--- pos %d ---\n%s", m.start(), js[start:end])

    log.info("=== FIN ===")


if __name__ == "__main__":
    main()
