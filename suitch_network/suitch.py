#!/usr/bin/env python3
"""
Suitch Network — Home Assistant Add-on — MODO DIAGNÓSTICO
Descarga /login completo y lo guarda en /data/login_page.html
"""

import json, logging, os, ssl, urllib.request, urllib.parse, http.cookiejar

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("suitch")

BASE_URL = "https://suitch.network"
SSL_CTX  = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"


def fetch(url):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=SSL_CTX),
    )
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
    with opener.open(req, timeout=15) as r:
        raw = r.read()
        if r.headers.get("Content-Encoding") == "gzip":
            import gzip; raw = gzip.decompress(raw)
        return raw.decode("utf-8", errors="replace"), dict(r.headers)


def main():
    # ── Descargar /login completo ──
    log.info("Descargando /login...")
    html, headers = fetch(f"{BASE_URL}/login")
    log.info("/login headers: %s", headers)
    log.info("/login completo (%d bytes):\n%s", len(html), html)

    # Guardar en archivo accesible
    out = "/data/login_page.html"
    with open(out, "w") as f:
        f.write(html)
    log.info("Guardado en %s", out)

    # ── Buscar src de scripts JS ──
    import re
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    log.info("Scripts JS encontrados: %s", scripts)

    # ── Descargar cada script JS local para buscar onSubmitAction ──
    for src in scripts:
        if src.startswith("http"):
            continue  # solo locales
        full_url = f"{BASE_URL}/{src.lstrip('/')}"
        try:
            js, _ = fetch(full_url)
            log.info("JS %s (%d bytes):\n%s", full_url, len(js), js[:3000])
        except Exception as e:
            log.warning("No se pudo descargar %s: %s", full_url, e)

    log.info("Diagnóstico completo. Revisa el log.")


if __name__ == "__main__":
    main()
