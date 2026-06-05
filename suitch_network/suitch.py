#!/usr/bin/env python3
"""
Suitch Network — Home Assistant Add-on
Sin dependencias externas (stdlib pura).
"""

import json
import logging
import os
import re
import ssl
import time
import urllib.request
import urllib.parse
import http.cookiejar
import html.parser
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("suitch")

BASE_URL = "https://suitch.network"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

BROWSER_HEADERS = {
    "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language":           "es-MX,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding":           "gzip, deflate, br",
    "Connection":                "keep-alive",
    "Sec-Ch-Ua":                 '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile":          "?0",
    "Sec-Ch-Ua-Platform":        '"Windows"',
    "Upgrade-Insecure-Requests": "1",
}


# ─────────────────────────────────────────────────────────────
#  Credenciales desde /data/options.json
# ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    options_file = "/data/options.json"
    if not os.path.exists(options_file):
        raise FileNotFoundError("No se encontró /data/options.json")
    with open(options_file, encoding="utf-8") as f:
        opts = json.load(f)
    email    = opts.get("email", "").strip()
    password = opts.get("password", "").strip()
    if not email or not password:
        raise ValueError("Email o password vacíos — revisa la pestaña 'Configuration'.")
    return {
        "email":         email,
        "password":      password,
        "scan_interval": int(opts.get("scan_interval", 60)),
    }


# ─────────────────────────────────────────────────────────────
#  HA Supervisor API
# ─────────────────────────────────────────────────────────────

HA_API   = "http://supervisor/core/api"
HA_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")


def ha_set_state(entity_id: str, state: Any, attributes: dict = {}) -> bool:
    url     = f"{HA_API}/states/{entity_id}"
    payload = json.dumps({"state": state, "attributes": attributes}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {HA_TOKEN}",
            "Content-Type":  "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status in (200, 201)
    except Exception as e:
        log.error("HA API error [%s]: %s", entity_id, e)
        return False


# ─────────────────────────────────────────────────────────────
#  Parsers de CSRF
# ─────────────────────────────────────────────────────────────

class _CSRFParser(html.parser.HTMLParser):
    """Busca el token en meta tags e inputs hidden."""
    def __init__(self):
        super().__init__()
        self.token: str | None = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name") == "csrf-token":
            self.token = attrs.get("content")
        if tag == "input" and attrs.get("name") == "authenticity_token":
            self.token = attrs.get("value")
        if attrs.get("data-authenticity-token"):
            self.token = attrs["data-authenticity-token"]


def _extract_csrf_from_html(html_text: str) -> str | None:
    """
    Busca el CSRF token en cualquier lugar del HTML/JS:
    - <meta name="csrf-token">
    - <input name="authenticity_token">
    - data-authenticity-token="..."
    - "authenticity_token":"..." en JSON embebido
    - window.csrfToken = "..."
    - gon.authenticity_token = "..."
    """
    # 1. Parser HTML estándar
    p = _CSRFParser()
    p.feed(html_text)
    if p.token:
        return p.token

    # 2. Regex en el HTML/JS — busca el token en cualquier forma
    patterns = [
        r'"authenticity_token"\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
        r'authenticity_token["\']?\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
        r'csrf[_\-]token["\']?\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
        r'csrfToken["\']?\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{20,})["\']',
        r'content="([A-Za-z0-9+/=_\-]{40,})"[^>]*name="csrf-token"',
        r'name="csrf-token"[^>]*content="([A-Za-z0-9+/=_\-]{40,})"',
    ]
    for pat in patterns:
        m = re.search(pat, html_text, re.IGNORECASE)
        if m:
            log.info("CSRF token encontrado vía regex: %s", pat)
            return m.group(1)

    return None


def _extract_csrf_from_cookies(jar: http.cookiejar.CookieJar) -> str | None:
    """Busca el CSRF token en las cookies (XSRF-TOKEN, csrf-token, etc.)."""
    csrf_names = {"xsrf-token", "csrf-token", "csrf_token", "x-csrf-token", "_csrf"}
    for cookie in jar:
        if cookie.name.lower() in csrf_names:
            log.info("CSRF token encontrado en cookie: %s", cookie.name)
            return urllib.parse.unquote(cookie.value)
    return None


# ─────────────────────────────────────────────────────────────
#  Cliente suitch.network
# ─────────────────────────────────────────────────────────────

class SuitchClient:
    def __init__(self, email: str, password: str):
        self._email    = email
        self._password = password
        self._jar      = http.cookiejar.CookieJar()
        self._opener   = self._new_opener()

    def _new_opener(self):
        self._jar = http.cookiejar.CookieJar()
        https_handler = urllib.request.HTTPSHandler(context=SSL_CTX)
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._jar),
            https_handler,
        )

    def _read(self, resp) -> bytes:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            import gzip
            raw = gzip.decompress(raw)
        return raw

    def _get_csrf(self) -> str:
        """Intenta obtener el CSRF token desde varias fuentes."""
        candidates = [
            f"{BASE_URL}/users/sign_in",
            f"{BASE_URL}/",
            f"{BASE_URL}/login",
        ]
        for url in candidates:
            try:
                req = urllib.request.Request(url, headers={
                    **BROWSER_HEADERS,
                    "Accept":           "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Sec-Fetch-Site":   "none",
                    "Sec-Fetch-Mode":   "navigate",
                    "Sec-Fetch-User":   "?1",
                    "Sec-Fetch-Dest":   "document",
                })
                with self._opener.open(req, timeout=15) as r:
                    status = r.status
                    raw    = self._read(r)

                html_text = raw.decode("utf-8", errors="replace")
                log.info("GET %s → %s (%d bytes)", url, status, len(html_text))

                # 1. Buscar en HTML/JS
                token = _extract_csrf_from_html(html_text)
                if token:
                    log.info("CSRF desde HTML en %s: %s...", url, token[:20])
                    return token

                # 2. Buscar en cookies
                token = _extract_csrf_from_cookies(self._jar)
                if token:
                    log.info("CSRF desde cookie: %s...", token[:20])
                    return token

                # Debug: listar cookies recibidas
                cookie_names = [c.name for c in self._jar]
                log.info("Cookies tras GET %s: %s", url, cookie_names)

            except Exception as e:
                log.warning("GET %s → %s", url, e)

        raise RuntimeError(
            "No se encontró el CSRF token. "
            "Revisa el log para ver qué cookies/HTML devuelve suitch.network."
        )

    def login(self) -> None:
        self._opener = self._new_opener()
        token = self._get_csrf()

        payload = urllib.parse.urlencode({
            "email":              self._email,
            "password":           self._password,
            "authenticity_token": token,
            "utf8":               "✓",
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{BASE_URL}/auth/v2/login.json",
            data=payload,
            method="POST",
            headers={
                **BROWSER_HEADERS,
                "Content-Type":     "application/x-www-form-urlencoded",
                "Accept":           "application/json, text/javascript, */*; q=0.01",
                "Referer":          f"{BASE_URL}/users/sign_in",
                "X-CSRF-Token":     token,
                "X-Requested-With": "XMLHttpRequest",
                "Sec-Fetch-Site":   "same-origin",
                "Sec-Fetch-Mode":   "cors",
                "Sec-Fetch-Dest":   "empty",
            },
        )
        with self._opener.open(req, timeout=15) as r:
            body = self._read(r)
            log.info("Login response (%s): %s", r.status, body[:300])
        log.info("Login exitoso en suitch.network")

    def devices(self) -> list[dict]:
        req = urllib.request.Request(
            f"{BASE_URL}/devices/v2/show.json",
            headers={
                **BROWSER_HEADERS,
                "Accept":           "application/json",
                "Referer":          f"{BASE_URL}/",
                "Sec-Fetch-Site":   "same-origin",
                "Sec-Fetch-Mode":   "cors",
                "Sec-Fetch-Dest":   "empty",
            },
        )
        with self._opener.open(req, timeout=15) as r:
            data = json.loads(self._read(r))
        return data if isinstance(data, list) else data.get("devices", [])


# ─────────────────────────────────────────────────────────────
#  Publicar dispositivos en HA
# ─────────────────────────────────────────────────────────────

def _unit_and_class(field: str):
    f = field.lower()
    if any(x in f for x in ("hum", "humidity", "humedad")):  return "%",  "humidity"
    if any(x in f for x in ("temp", "temperatura")):         return "°C", "temperature"
    if any(x in f for x in ("volt", "voltage")):             return "V",  "voltage"
    if any(x in f for x in ("amp", "current", "corriente")): return "A",  "current"
    return None, None


def publish_device(dev: dict) -> None:
    uid  = str(dev.get("uid") or dev.get("id") or "unknown")
    name = dev.get("name") or dev.get("label") or uid
    slug = name.lower().replace(" ", "_")

    numeric_found = False
    for field, value in dev.items():
        if not isinstance(value, (int, float)):
            continue
        numeric_found = True
        entity_id = f"sensor.suitch_{slug}_{field.lower()}"
        unit, dev_class = _unit_and_class(field)
        attrs = {
            "friendly_name": f"Suitch {name} {field}",
            "device_uid":    uid,
            "source":        "suitch.network",
        }
        if unit:      attrs["unit_of_measurement"] = unit
        if dev_class: attrs["device_class"]        = dev_class
        ok = ha_set_state(entity_id, value, attrs)
        log.info("  %-45s = %s %s [%s]", entity_id, value, unit or "", "OK" if ok else "FAIL")

    if not numeric_found:
        ha_set_state(f"sensor.suitch_{slug}_state", "online", {
            "friendly_name": f"Suitch {name}", "device_uid": uid, "raw": dev,
        })


# ─────────────────────────────────────────────────────────────
#  Main loop
# ─────────────────────────────────────────────────────────────

def main() -> None:
    cfg      = load_config()
    client   = SuitchClient(cfg["email"], cfg["password"])
    interval = cfg["scan_interval"]

    log.info("Addon arrancado — polling cada %ds", interval)

    client.login()

    while True:
        try:
            devs = client.devices()
            log.info("── %d dispositivo(s) ──", len(devs))
            for dev in devs:
                publish_device(dev)
        except Exception as e:
            log.warning("Error polling (%s) — re-login...", e)
            try:
                client.login()
            except Exception as le:
                log.error("Re-login fallido: %s — reintentando en %ds", le, interval)

        time.sleep(interval)


if __name__ == "__main__":
    main()
