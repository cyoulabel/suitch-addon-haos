#!/usr/bin/env python3
"""
Suitch Network — Home Assistant Add-on
Sin dependencias externas (stdlib pura).
"""

import json
import logging
import os
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

# Headers que imitan un browser real — evitan el 403
BROWSER_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "es-MX,es;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}


# ─────────────────────────────────────────────────────────────
#  Credenciales desde /data/options.json (UI del addon)
# ─────────────────────────────────────────────────────────────

def load_config() -> dict:
    options_file = "/data/options.json"
    if not os.path.exists(options_file):
        raise FileNotFoundError(
            "No se encontró /data/options.json — "
            "configura email y password en la pestaña 'Configuration' del addon."
        )
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
#  Cliente suitch.network
# ─────────────────────────────────────────────────────────────

class _CSRFParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.token: str | None = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and attrs.get("name") == "csrf-token":
            self.token = attrs.get("content")
        if tag == "input" and attrs.get("name") == "authenticity_token":
            self.token = attrs.get("value")


class SuitchClient:
    def __init__(self, email: str, password: str):
        self._email    = email
        self._password = password
        self._opener   = self._new_opener()

    def _new_opener(self):
        jar = http.cookiejar.CookieJar()
        https_handler = urllib.request.HTTPSHandler(context=SSL_CTX)
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            https_handler,
        )

    def _get(self, url: str, accept="application/json") -> bytes:
        req = urllib.request.Request(url, headers={
            **BROWSER_HEADERS,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                      if accept == "text/html" else accept,
        })
        with self._opener.open(req, timeout=15) as r:
            raw = r.read()
            # descomprimir gzip si aplica
            if r.headers.get("Content-Encoding") == "gzip":
                import gzip
                raw = gzip.decompress(raw)
            return raw

    def _post(self, url: str, data: dict, extra: dict = {}) -> bytes:
        payload = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={
                **BROWSER_HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept":        "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                **extra,
            },
        )
        with self._opener.open(req, timeout=15) as r:
            raw = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                import gzip
                raw = gzip.decompress(raw)
            return raw

    def _csrf(self) -> str:
        raw = self._get(f"{BASE_URL}/users/sign_in", accept="text/html")
        p = _CSRFParser()
        p.feed(raw.decode("utf-8", errors="replace"))
        if not p.token:
            raise RuntimeError("CSRF token no encontrado")
        log.info("CSRF token obtenido")
        return p.token

    def login(self) -> None:
        self._opener = self._new_opener()
        token = self._csrf()
        self._post(
            f"{BASE_URL}/auth/v2/login.json",
            data={
                "email": self._email, "password": self._password,
                "authenticity_token": token, "utf8": "✓",
            },
            extra={
                "Referer":      f"{BASE_URL}/users/sign_in",
                "X-CSRF-Token": token,
            },
        )
        log.info("Login exitoso en suitch.network")

    def devices(self) -> list[dict]:
        raw  = self._get(f"{BASE_URL}/devices/v2/show.json")
        data = json.loads(raw)
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
