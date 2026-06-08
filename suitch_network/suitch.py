#!/usr/bin/env python3
"""
Suitch Network — Home Assistant Add-on
Sin dependencias externas (stdlib pura).

Flujo de login corregido para emular la web de suitch.network (Rails):
    1) GET  /auth/v2/verify.json   -> devuelve {"token": "..."} (CSRF) y deja
                                      la cookie de sesion en el cookie jar.
    2) POST /auth/v2/login.json    -> con email, password, authenticity_token
                                      (el token de verify) y utf8 = "✓".
La autenticacion posterior se mantiene por la COOKIE de sesion (no Bearer).
El authenticity_token solo se usa como proteccion CSRF en peticiones POST/PUT.
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
        "insecure_ssl":  bool(opts.get("insecure_ssl", False)),
    }


def load_saved_token() -> str:
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, encoding="utf-8") as f:
            t = f.read().strip()
            if t:
                return t
    return ""


def save_token(token: str) -> None:
    try:
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(token)
    except OSError as e:
        log.warning("No se pudo guardar el token: %s", e)


HA_API   = "http://supervisor/core/api"
HA_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")


def ha_set_state(entity_id: str, state: Any, attributes: dict | None = None) -> bool:
    payload = json.dumps({"state": state, "attributes": attributes or {}}).encode("utf-8")
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
    def __init__(self, email: str, password: str, initial_token: str = "", insecure_ssl: bool = False):
        self._email    = email
        self._password = password
        self._token    = initial_token  # authenticity_token (CSRF)
        self._ssl_ctx  = self._build_ssl_ctx(insecure_ssl)
        self._opener   = self._new_opener()

    @staticmethod
    def _build_ssl_ctx(insecure: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            log.warning("SSL verification DESACTIVADA (insecure_ssl=true)")
        return ctx

    def _new_opener(self):
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=self._ssl_ctx),
        )

    def _read(self, resp) -> bytes:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            import gzip
            raw = gzip.decompress(raw)
        return raw

    def _base_headers(self) -> dict:
        return {
            "User-Agent": UA,
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }

    def _get_json(self, url: str, label: str) -> Any:
        req = urllib.request.Request(url, headers=self._base_headers())
        try:
            with self._opener.open(req, timeout=15) as r:
                body = self._read(r)
                return json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            log.warning("[GET %s] → %s: %s", label, e.code, body[:300])
            raise

    def _post_json(self, url: str, data: dict, label: str) -> Any:
        payload = json.dumps(data).encode("utf-8")
        headers = self._base_headers()
        headers["Content-Type"] = "application/json"
        if self._token:
            # Rails tambien acepta el CSRF token por cabecera.
            headers["X-CSRF-Token"] = self._token
        req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
        try:
            with self._opener.open(req, timeout=15) as r:
                body = self._read(r)
                log.info("[%s] → %s", label, r.status)
                return json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            log.warning("[%s] → %s: %s", label, e.code, body[:300])
            return None

    # ──────────────────────────── LOGIN ────────────────────────────
    def login(self) -> None:
        # Cookie jar nuevo en cada (re)login para evitar sesiones zombie.
        self._opener = self._new_opener()

        # 1) Capturar el token de verify (CSRF) y la cookie de sesion.
        token = self._fetch_verify_token()
        if not token:
            raise RuntimeError(
                "No se pudo obtener el token de /auth/v2/verify.json. "
                "¿Cambió la API de suitch.network?"
            )

        # 2) Login con el token capturado (mismo payload que la web Vue).
        resp = self._post_json(
            f"{BASE_URL}/auth/v2/login.json",
            {
                "email": self._email,
                "password": self._password,
                "authenticity_token": token,
                "utf8": "✓",
            },
            "login",
        )

        if resp is None:
            raise RuntimeError(
                "Login rechazado por el servidor. Revisa email/password.\n"
                "El token de verify se capturó bien, así que el problema es credenciales o API."
            )
        if isinstance(resp, dict) and (resp.get("errors") or resp.get("error")):
            raise RuntimeError(f"Login con error: {resp.get('errors') or resp.get('error')}")

        # 3) Si el login devuelve un token rotado, lo usamos a partir de ahora
        #    (la web hace lo mismo: JwtService.saveToken(user.token)).
        self._extract_token(resp)
        log.info("Login exitoso")

    def _fetch_verify_token(self) -> str:
        log.info("GET /auth/v2/verify.json (capturando token CSRF)")
        data = self._get_json(f"{BASE_URL}/auth/v2/verify.json", "verify")
        token = ""
        if isinstance(data, dict):
            token = data.get("token") or data.get("authenticity_token") or ""
        if token:
            self._token = token
            save_token(token)
            log.info("Token de verify capturado: %s…", token[:16])
        return token

    def _extract_token(self, resp: Any) -> None:
        if not isinstance(resp, dict):
            return
        new_token = (
            resp.get("token") or resp.get("authenticity_token") or
            resp.get("id_token") or resp.get("jwt") or resp.get("access_token")
        )
        if new_token and new_token != self._token:
            self._token = new_token
            save_token(new_token)
            log.info("Token rotado tras login: %s…", str(new_token)[:16])

    def _ensure_logged_in_get(self, url: str, label: str) -> Any:
        """GET que re-loguea automaticamente si la sesion expiro (401/403)."""
        try:
            return self._get_json(url, label)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                log.info("Sesión expirada (%s) — re-login…", e.code)
                self.login()
                return self._get_json(url, label)
            raise

    # ──────────────────────────── DATOS ────────────────────────────
    def devices(self) -> list[dict]:
        data = self._ensure_logged_in_get(f"{BASE_URL}/devices/v2/show.json", "devices")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("devices", []) or []
        return []

    def device_props(self, token: str) -> list[dict]:
        """Lecturas reales de sensores: lista de {command, value, unit, ...}."""
        try:
            data = self._ensure_logged_in_get(
                f"{BASE_URL}/devices/v2/{token}/props.json", f"props/{token}"
            )
        except urllib.error.HTTPError:
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("props", []) or []
        return []

    def device_battery(self, token: str) -> dict | None:
        try:
            data = self._ensure_logged_in_get(
                f"{BASE_URL}/devices/v2/{token}/battery.json", f"battery/{token}"
            )
        except urllib.error.HTTPError:
            return None
        return data if isinstance(data, dict) else None


def _unit_and_class(field: str, unit: str = ""):
    f = f"{field} {unit}".lower()
    if any(x in f for x in ("hum", "humidity", "humedad")):  return (unit or "%"),  "humidity"
    if any(x in f for x in ("temp", "temperatura", "°c")):   return (unit or "°C"), "temperature"
    if any(x in f for x in ("volt", "voltage", "voltaje")):  return (unit or "V"),  "voltage"
    if any(x in f for x in ("amp", "current", "corriente")): return (unit or "A"),  "current"
    if any(x in f for x in ("batt", "bater")):               return (unit or "%"),  "battery"
    if any(x in f for x in ("press", "presion", "hpa")):     return (unit or "hPa"),"pressure"
    if any(x in f for x in ("lux", "illum", "luz")):         return (unit or "lx"), "illuminance"
    if any(x in f for x in ("co2", "ppm")):                  return (unit or "ppm"),"carbon_dioxide"
    return (unit or None), None


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in s.lower()).strip("_")


def publish_device(client: "SuitchClient", dev: dict) -> None:
    token = str(dev.get("token") or dev.get("uid") or dev.get("id") or "unknown")
    name  = dev.get("object") or dev.get("name") or dev.get("label") or token
    slug  = _slug(str(name)) or _slug(token)
    published = False

    # 1) Lecturas reales desde props.json (fuente principal de datos).
    for prop in client.device_props(token):
        label = str(prop.get("command") or prop.get("name") or prop.get("label") or "value")
        value = prop.get("value")
        unit  = str(prop.get("unit") or "")
        if value is None:
            continue
        entity_id = f"sensor.suitch_{slug}_{_slug(label)}"
        u, dev_class = _unit_and_class(label, unit)
        attrs = {"friendly_name": f"Suitch {name} {label}", "device_token": token, "source": "suitch.network"}
        if u:         attrs["unit_of_measurement"] = u
        if dev_class: attrs["device_class"] = dev_class
        ok = ha_set_state(entity_id, value, attrs)
        published = True
        log.info("  %-48s = %s %s [%s]", entity_id, value, u or "", "OK" if ok else "FAIL")

    # 2) Bateria como entidad dedicada.
    batt = client.device_battery(token)
    if isinstance(batt, dict):
        level = batt.get("level") or batt.get("percentage") or batt.get("value")
        if level is not None:
            ha_set_state(
                f"sensor.suitch_{slug}_battery", level,
                {"friendly_name": f"Suitch {name} Battery", "device_token": token,
                 "unit_of_measurement": "%", "device_class": "battery", "source": "suitch.network"},
            )
            published = True

    # 3) Campos numericos del propio device (fallback).
    for field, value in dev.items():
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        entity_id = f"sensor.suitch_{slug}_{_slug(field)}"
        u, dev_class = _unit_and_class(field)
        attrs = {"friendly_name": f"Suitch {name} {field}", "device_token": token, "source": "suitch.network"}
        if u:         attrs["unit_of_measurement"] = u
        if dev_class: attrs["device_class"] = dev_class
        ha_set_state(entity_id, value, attrs)
        published = True

    # 4) Si no hubo nada numerico, al menos un estado de presencia.
    if not published:
        ha_set_state(f"sensor.suitch_{slug}_state", "online",
                     {"friendly_name": f"Suitch {name}", "device_token": token, "raw": dev})


def main() -> None:
    cfg   = load_config()
    token = cfg["id_token"] or load_saved_token()

    client   = SuitchClient(cfg["email"], cfg["password"], token, cfg["insecure_ssl"])
    interval = cfg["scan_interval"]

    log.info("Addon arrancado — polling cada %ds", interval)
    client.login()

    while True:
        try:
            devs = client.devices()
            log.info("── %d dispositivo(s) ──", len(devs))
            for dev in devs:
                publish_device(client, dev)
        except Exception as e:
            log.warning("Error polling (%s) — re-login…", e)
            try:
                client.login()
            except Exception as le:
                log.error("Re-login fallido: %s", le)
        time.sleep(interval)


if __name__ == "__main__":
    main()
