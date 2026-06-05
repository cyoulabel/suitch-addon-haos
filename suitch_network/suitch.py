#!/usr/bin/env python3
"""
Suitch Network — Home Assistant Add-on
Sin dependencias externas (stdlib pura).

MECANISMO DE AUTENTICACIÓN:
  El app.js usa localStorage.getItem("id_token") como authenticity_token.
  Para bootstrap, el usuario pega su id_token del browser en la config.
  Tras el primer login, el token se renueva automáticamente desde /data/id_token.txt
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

BASE_URL    = "https://suitch.network"
TOKEN_FILE  = "/data/id_token.txt"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode    = ssl.CERT_NONE

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


# ─────────────────────────────────────────────────────────────
#  Configuración
# ─────────────────────────────────────────────────────────────

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
    """Lee el id_token persistido en /data/id_token.txt."""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, encoding="utf-8") as f:
            t = f.read().strip()
            if t:
                log.info("Token cargado desde %s", TOKEN_FILE)
                return t
    return ""


def save_token(token: str) -> None:
    """Guarda el id_token en /data/id_token.txt para futuras sesiones."""
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        f.write(token)
    log.info("Token guardado en %s", TOKEN_FILE)


# ─────────────────────────────────────────────────────────────
#  HA Supervisor API
# ─────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────
#  Cliente suitch.network
# ─────────────────────────────────────────────────────────────

class SuitchClient:
    def __init__(self, email: str, password: str, initial_token: str = ""):
        self._email    = email
        self._password = password
        self._token    = initial_token   # id_token actual (se renueva tras cada login)
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

    def login(self) -> None:
        self._opener = self._new_opener()

        if not self._token:
            raise RuntimeError(
                "No hay id_token disponible.\n"
                "Para el primer login:\n"
                "  1. Abre Chrome → DevTools (F12) → Application\n"
                "  2. Storage → Local Storage → https://suitch.network\n"
                "  3. Copia el valor de 'id_token'\n"
                "  4. Pégalo en Configuration → id_token del addon"
            )

        log.info("Haciendo login con id_token: %s...", self._token[:20])

        payload = json.dumps({
            "email":              self._email,
            "password":           self._password,
            "authenticity_token": self._token,
            "utf8":               "✓",
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{BASE_URL}/auth/v2/login.json",
            data=payload,
            method="POST",
            headers={
                "User-Agent":   UA,
                "Content-Type": "application/json",
                "Accept":       "application/json",
            },
        )
        with self._opener.open(req, timeout=15) as r:
            body = self._read(r)
            log.info("Login response (%s): %s", r.status, body[:500])
            resp = json.loads(body)

        # Guardar el nuevo token que devuelve el servidor
        new_token = (
            resp.get("id_token") or
            resp.get("token") or
            resp.get("authenticity_token") or
            resp.get("jwt") or
            resp.get("access_token")
        )
        if new_token:
            self._token = new_token
            save_token(new_token)
            log.info("Nuevo id_token guardado: %s...", new_token[:20])
        else:
            log.info("Login OK — respuesta completa: %s", resp)

        log.info("Login exitoso")

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
        attrs = {"friendly_name": f"Suitch {name} {field}", "device_uid": uid, "source": "suitch.network"}
        if unit:      attrs["unit_of_measurement"] = unit
        if dev_class: attrs["device_class"]        = dev_class
        ok = ha_set_state(entity_id, value, attrs)
        log.info("  %-45s = %s %s [%s]", entity_id, value, unit or "", "OK" if ok else "FAIL")
    if not numeric_found:
        ha_set_state(f"sensor.suitch_{slug}_state", "online",
                     {"friendly_name": f"Suitch {name}", "device_uid": uid, "raw": dev})


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main() -> None:
    cfg = load_config()

    # Prioridad de token: config → archivo guardado
    token = cfg["id_token"] or load_saved_token()
    if token:
        save_token(token)   # normalizar siempre a archivo

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
