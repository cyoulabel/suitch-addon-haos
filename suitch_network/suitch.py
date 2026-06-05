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

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def load_config() -> dict:
    with open("/data/options.json", encoding="utf-8") as f:
        opts = json.load(f)
    email    = opts.get("email", "").strip()
    password = opts.get("password", "").strip()
    if not email or not password:
        raise ValueError("Email o password vacíos — revisa Configuration.")
    return {
        "email":         email,
        "password":      password,
        "scan_interval": int(opts.get("scan_interval", 60)),
    }


HA_API   = "http://supervisor/core/api"
HA_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")


def ha_set_state(entity_id: str, state: Any, attributes: dict = {}) -> bool:
    payload = json.dumps({"state": state, "attributes": attributes}).encode("utf-8")
    req = urllib.request.Request(
        f"{HA_API}/states/{entity_id}", data=payload, method="POST",
        headers={"Authorization": f"Bearer {HA_TOKEN}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status in (200, 201)
    except Exception as e:
        log.error("HA API error [%s]: %s", entity_id, e)
        return False


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

    def _get_csrf(self) -> str:
        """
        Obtiene el CSRF token desde la página principal con regex robusta.
        El token está en <meta name="csrf-token" content="..."> cerca del
        final de los 72KB de HTML (después del JS de New Relic).
        """
        req = urllib.request.Request(
            f"{BASE_URL}/",
            headers={
                "User-Agent":    UA,
                "Accept":        "text/html,application/xhtml+xml,*/*;q=0.8",
                "Cache-Control": "no-cache",
            },
        )
        with self._opener.open(req, timeout=20) as r:
            raw  = self._read(r)
            text = raw.decode("utf-8", errors="replace")

        log.info("GET / → %s (%d bytes)", r.status, len(text))

        # Regex que funciona aunque el tag esté en cualquier posición
        # y aunque html.parser falle por el JS minificado de NR
        patterns = [
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta[^>]*content=["\']([A-Za-z0-9+/=_\-]{40,})["\'][^>]*name=["\']csrf-token["\']',
            r'csrf-token["\'][^>]*content=["\']([A-Za-z0-9+/=_\-]{40,})["\']',
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.DOTALL)
            if m:
                token = m.group(1)
                log.info("CSRF token encontrado (%d chars): %s...", len(token), token[:20])
                return token

        # Debug — mostrar últimos 500 chars donde debería estar el token
        log.warning("Token NO encontrado. Últimos 500 chars: %s", text[-500:])
        raise RuntimeError("No se encontró csrf-token en la página /")

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
                "User-Agent":       UA,
                "Content-Type":     "application/x-www-form-urlencoded",
                "Accept":           "application/json",
                "Referer":          f"{BASE_URL}/",
                "X-CSRF-Token":     token,
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        with self._opener.open(req, timeout=15) as r:
            body = self._read(r)
            log.info("Login response (%s): %s", r.status, body[:300])
        log.info("Login exitoso en suitch.network")

    def devices(self) -> list[dict]:
        req = urllib.request.Request(
            f"{BASE_URL}/devices/v2/show.json",
            headers={"User-Agent": UA, "Accept": "application/json"},
        )
        with self._opener.open(req, timeout=15) as r:
            data = json.loads(self._read(r))
        return data if isinstance(data, list) else data.get("devices", [])


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
        attrs = {"friendly_name": f"Suitch {name} {field}", "device_uid": uid, "source": "suitch.network"}
        if unit:      attrs["unit_of_measurement"] = unit
        if dev_class: attrs["device_class"]        = dev_class
        ok = ha_set_state(entity_id, value, attrs)
        log.info("  %-45s = %s %s [%s]", entity_id, value, unit or "", "OK" if ok else "FAIL")
    if not numeric_found:
        ha_set_state(f"sensor.suitch_{slug}_state", "online",
                     {"friendly_name": f"Suitch {name}", "device_uid": uid, "raw": dev})


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
                log.error("Re-login fallido: %s", le)
        time.sleep(interval)


if __name__ == "__main__":
    main()
