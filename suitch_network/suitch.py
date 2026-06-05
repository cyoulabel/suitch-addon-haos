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
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept-Language": "es-MX,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection":      "keep-alive",
}


# ─────────────────────────────────────────────────────────────
#  Credenciales
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
        headers={"Authorization": f"Bearer {HA_TOKEN}", "Content-Type": "application/json"},
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

class SuitchClient:
    def __init__(self, email: str, password: str):
        self._email    = email
        self._password = password
        self._opener   = self._new_opener()

    def _new_opener(self):
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=SSL_CTX),
        )

    def _read(self, resp) -> bytes:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            import gzip
            raw = gzip.decompress(raw)
        return raw

    def _try_login(self, url: str, payload: bytes, headers: dict) -> bool:
        """Intenta un login, devuelve True si exitoso, False si 4xx."""
        try:
            req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
            with self._opener.open(req, timeout=15) as r:
                body = self._read(r)
                log.info("  ✓ %s → %s: %s", url, r.status, body[:200])
                return True
        except urllib.error.HTTPError as e:
            body = e.read()[:300]
            log.warning("  ✗ %s → %s: %s", url, e.code, body)
            return False
        except Exception as e:
            log.warning("  ✗ %s → %s", url, e)
            return False

    def login(self) -> None:
        self._opener = self._new_opener()
        log.info("Intentando login en suitch.network...")

        # ── Intento 1: JSON a /auth/v2/login.json (sin CSRF — Rails lo omite para JSON) ──
        log.info("Intento 1: JSON → /auth/v2/login.json")
        payload = json.dumps({"email": self._email, "password": self._password}).encode("utf-8")
        if self._try_login(
            f"{BASE_URL}/auth/v2/login.json",
            payload,
            {**BROWSER_HEADERS,
             "Content-Type": "application/json",
             "Accept": "application/json",
             "X-Requested-With": "XMLHttpRequest"},
        ):
            return

        # ── Intento 2: JSON Devise estándar → /users/sign_in.json ──
        log.info("Intento 2: JSON Devise → /users/sign_in.json")
        payload = json.dumps({"user": {"email": self._email, "password": self._password}}).encode("utf-8")
        if self._try_login(
            f"{BASE_URL}/users/sign_in.json",
            payload,
            {**BROWSER_HEADERS,
             "Content-Type": "application/json",
             "Accept": "application/json"},
        ):
            return

        # ── Intento 3: form-encoded sin CSRF → /auth/v2/login.json ──
        log.info("Intento 3: form-encoded sin CSRF → /auth/v2/login.json")
        payload = urllib.parse.urlencode({
            "email": self._email, "password": self._password, "utf8": "✓",
        }).encode("utf-8")
        if self._try_login(
            f"{BASE_URL}/auth/v2/login.json",
            payload,
            {**BROWSER_HEADERS,
             "Content-Type": "application/x-www-form-urlencoded",
             "Accept": "application/json",
             "X-Requested-With": "XMLHttpRequest"},
        ):
            return

        # ── Intento 4: form-encoded sin CSRF → /users/sign_in ──
        log.info("Intento 4: form-encoded sin CSRF → /users/sign_in")
        payload = urllib.parse.urlencode({
            "user[email]": self._email, "user[password]": self._password, "utf8": "✓",
        }).encode("utf-8")
        if self._try_login(
            f"{BASE_URL}/users/sign_in",
            payload,
            {**BROWSER_HEADERS,
             "Content-Type": "application/x-www-form-urlencoded",
             "Accept": "application/json, text/html",
             "X-Requested-With": "XMLHttpRequest"},
        ):
            return

        raise RuntimeError(
            "Todos los intentos de login fallaron. "
            "Revisa el log para ver las respuestas del servidor."
        )

    def devices(self) -> list[dict]:
        req = urllib.request.Request(
            f"{BASE_URL}/devices/v2/show.json",
            headers={**BROWSER_HEADERS, "Accept": "application/json"},
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
