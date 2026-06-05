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
import urllib.error
import http.cookiejar
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("suitch")

BASE_URL   = "https://suitch.network"
TOKEN_FILE = "/data/id_token.txt"

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
        "id_token":      opts.get("id_token", "").strip(),
    }


def load_saved_token() -> str:
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, encoding="utf-8") as f:
            t = f.read().strip()
            if t:
                return t
    return ""


def save_token(token: str) -> None:
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(token)


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
    def __init__(self, email: str, password: str, initial_token: str = ""):
        self._email    = email
        self._password = password
        self._token    = initial_token
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

    def _try_login(self, payload: bytes, content_type: str, label: str) -> bool:
        req = urllib.request.Request(
            f"{BASE_URL}/auth/v2/login.json",
            data=payload,
            method="POST",
            headers={
                "User-Agent":   UA,
                "Content-Type": content_type,
                "Accept":       "application/json",
            },
        )
        try:
            with self._opener.open(req, timeout=15) as r:
                body = self._read(r)
                log.info("[%s] Login OK (%s): %s", label, r.status, body[:500])
                resp = json.loads(body)
                new_token = (
                    resp.get("id_token") or resp.get("token") or
                    resp.get("authenticity_token") or resp.get("jwt") or
                    resp.get("access_token")
                )
                if new_token:
                    self._token = new_token
                    save_token(new_token)
                    log.info("Nuevo token guardado: %s...", new_token[:20])
                else:
                    log.info("Login OK sin nuevo token — respuesta: %s", resp)
                return True
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            log.warning("[%s] → %s: %s", label, e.code, body)
            return False

    def login(self) -> None:
        self._opener = self._new_opener()

        if not self._token:
            raise RuntimeError(
                "No hay id_token.\n"
                "Abre Chrome → F12 → Application → Local Storage → suitch.network\n"
                "Copia 'id_token' y pégalo en Configuration del addon."
            )

        log.info("Login con token: %s... (%d chars)", self._token[:20], len(self._token))

        # Intento 1: JSON (como envía axios en el app.js)
        payload_json = json.dumps({
            "email":              self._email,
            "password":           self._password,
            "authenticity_token": self._token,
            "utf8":               "✓",
        }).encode("utf-8")

        if self._try_login(payload_json, "application/json", "JSON"):
            return

        # Intento 2: form-encoded
        payload_form = urllib.parse.urlencode({
            "email":              self._email,
            "password":           self._password,
            "authenticity_token": self._token,
            "utf8":               "✓",
        }).encode("utf-8")

        if self._try_login(payload_form, "application/x-www-form-urlencoded", "FORM"):
            return

        raise RuntimeError("Login fallido en ambos formatos. Revisa el log.")

    def devices(self) -> list[dict]:
        req = urllib.request.Request(
            f"{BASE_URL}/devices/v2/show.json",
            headers={
                "User-Agent":    UA,
                "Accept":        "application/json",
                "Authorization": f"Bearer {self._token}" if self._token else "",
            },
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
    cfg   = load_config()
    token = cfg["id_token"] or load_saved_token()
    if token and cfg["id_token"]:
        save_token(token)

    client   = SuitchClient(cfg["email"], cfg["password"], token)
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
