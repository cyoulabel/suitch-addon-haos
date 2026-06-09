#!/usr/bin/env python3
"""
Suitch Network — Home Assistant Add-on
Publica sensores vía MQTT Discovery → aparecen como Devices en HA.
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

import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("suitch")

BASE_URL    = "https://suitch.network"
TOKEN_FILE  = "/data/id_token.txt"
DISC_PREFIX = "homeassistant"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


# ─────────────────────────────────────────────────────────────
#  Config
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
        "insecure_ssl":  bool(opts.get("insecure_ssl", False)),
        "mqtt_host":     opts.get("mqtt_host", "core-mosquitto"),
        "mqtt_port":     int(opts.get("mqtt_port", 1883)),
        "mqtt_user":     opts.get("mqtt_user", ""),
        "mqtt_password": opts.get("mqtt_password", ""),
    }


def load_saved_token() -> str:
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, encoding="utf-8") as f:
            t = f.read().strip()
            if t: return t
    return ""


def save_token(token: str) -> None:
    try:
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(token)
    except OSError as e:
        log.warning("No se pudo guardar el token: %s", e)


# ─────────────────────────────────────────────────────────────
#  Helpers de campo
# ─────────────────────────────────────────────────────────────

def _unit_class_icon(field: str, unit: str = "") -> tuple[str | None, str | None, str | None]:
    f = f"{field} {unit}".lower()
    if any(x in f for x in ("moisture", "hum", "humidity", "humedad")):
        return (unit or None), "humidity",          "mdi:water-percent"
    if any(x in f for x in ("temp", "temperatura", "°c")):
        return (unit or "°C"),  "temperature",       "mdi:thermometer"
    if any(x in f for x in ("press", "hpa", "pa")):
        return "hPa",           "pressure",          "mdi:gauge"
    if any(x in f for x in ("volt", "voltage")):
        return (unit or "V"),   "voltage",           "mdi:lightning-bolt"
    if any(x in f for x in ("amp", "current")):
        return (unit or "A"),   "current",           "mdi:current-ac"
    if any(x in f for x in ("power", "watt", " w ")):
        return (unit or "W"),   "power",             "mdi:flash"
    if any(x in f for x in ("batt", "bater")):
        return (unit or "%"),   "battery",           "mdi:battery"
    if any(x in f for x in ("lux", "illum")):
        return (unit or "lx"),  "illuminance",       "mdi:white-balance-sunny"
    if any(x in f for x in ("co2", "ppm")):
        return (unit or "ppm"), "carbon_dioxide",    "mdi:molecule-co2"
    if "magnet" in f:
        return (unit or "µT"),  None,                "mdi:magnet"
    if "accel" in f:
        return (unit or "m/s²"), None,               "mdi:axis-arrow"
    if "gyro" in f:
        return (unit or "°/s"), None,                "mdi:rotate-3d-variant"
    if "location" in f:
        return None,            None,                "mdi:map-marker"
    if "bt_key" in f or "bluetooth" in f:
        return None,            None,                "mdi:bluetooth"
    return (unit or None), None, None


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in s.lower()).strip("_")


_SKIP_FIELDS = {
    "token", "uid", "id", "object", "name", "label", "type", "device_type",
    "rig_id", "rig_id_owner", "rig_is_public", "rig_likes", "rig_connection_type",
    "id_owner", "is_public", "likes", "connection_type",
    "created_at", "updated_at", "user_id", "firmware", "hardware", "description",
    "notify_email", "notify_twitter", "notify_fbinbox", "notify_telegram",
    "fav",
}
_SKIP_PROPS = {
    "id", "id_owner", "owner", "is_public", "public", "likes", "connection_type",
    "connection", "created_at", "updated_at", "firmware", "hardware",
    "rig_id", "rig_id_owner", "rig_is_public", "rig_likes", "rig_connection_type",
    "token", "uid", "name", "label", "type", "description",
    "notify_email", "notify_twitter", "notify_fbinbox", "notify_telegram",
    "fav",
}

# Campos XYZ que se deben separar en ejes
_XYZ_FIELDS = {"magnetometer", "accelaration", "acceleration", "gyroscope"}


def _parse_xyz(value: str) -> tuple[float, float, float] | None:
    """Parsea '308,419,92' → (308.0, 419.0, 92.0). Devuelve None si falla."""
    try:
        parts = [float(p.strip()) for p in str(value).split(",")]
        if len(parts) == 3:
            return tuple(parts)
    except (ValueError, AttributeError):
        pass
    return None


def _pa_to_hpa(value: Any) -> float | None:
    """Convierte Pa a hPa si el valor es mayor a 10000 (claramente en Pa)."""
    try:
        v = float(str(value).split()[0])
        return round(v / 100, 2) if v > 10000 else v
    except (ValueError, AttributeError):
        return None


# ─────────────────────────────────────────────────────────────
#  MQTT
# ─────────────────────────────────────────────────────────────

class MQTTPublisher:
    def __init__(self, host: str, port: int, user: str, password: str):
        self._host     = host
        self._port     = port
        self._user     = user
        self._password = password
        self._client   = None
        self._connect()

    def _connect(self) -> None:
        c = mqtt.Client(client_id="suitch_addon", protocol=mqtt.MQTTv311)
        if self._user:
            c.username_pw_set(self._user, self._password)
        c.on_connect    = lambda cl, ud, fl, rc: log.info("MQTT conectado (rc=%s)", rc)
        c.on_disconnect = lambda cl, ud, rc:     log.warning("MQTT desconectado (rc=%s)", rc)
        try:
            c.connect(self._host, self._port, keepalive=60)
            c.loop_start()
            time.sleep(1)
            self._client = c
            log.info("MQTT → %s:%s", self._host, self._port)
        except Exception as e:
            log.error("No se pudo conectar a MQTT: %s", e)
            self._client = None

    def publish(self, topic: str, payload: str, retain: bool = False) -> None:
        if self._client is None:
            self._connect()
        if self._client:
            self._client.publish(topic, payload, qos=1, retain=retain)

    def announce(self, device_token: str, device_name: str, field: str,
                 unit: str | None, device_class: str | None,
                 icon: str | None) -> str:
        unique_id   = f"suitch_{device_token}_{field}"
        state_topic = f"suitch/{device_token}/{field}/state"
        payload = {
            "name":        f"{device_name} {field}".strip(),
            "unique_id":   unique_id,
            "state_topic": state_topic,
            "device": {
                "identifiers":  [f"suitch_{device_token}"],
                "name":         f"Suitch {device_name}",
                "manufacturer": "Suitch",
                "model":        "suitch.network",
            },
        }
        if unit:         payload["unit_of_measurement"] = unit
        if device_class: payload["device_class"]        = device_class
        if icon:         payload["icon"]                = icon
        config_topic = f"{DISC_PREFIX}/sensor/{unique_id}/config"
        self.publish(config_topic, json.dumps(payload), retain=True)
        return state_topic

    def purge_all(self) -> None:
        """Borra todos los dispositivos Suitch del broker publicando payload vacío con retain."""
        import time as _time
        log.info("Limpiando dispositivos Suitch anteriores del broker MQTT…")
        # Suscribirse temporalmente a homeassistant/sensor/suitch_*/config
        found = []
        def _on_msg(cl, ud, msg):
            if msg.payload:
                found.append(msg.topic)

        tmp = mqtt.Client(client_id="suitch_purge", protocol=mqtt.MQTTv311)
        if self._user:
            tmp.username_pw_set(self._user, self._password)
        tmp.on_message = _on_msg
        try:
            tmp.connect(self._host, self._port, keepalive=30)
            tmp.subscribe("homeassistant/sensor/suitch_+/config", qos=1)
            tmp.loop_start()
            _time.sleep(2)          # esperar mensajes retenidos
            tmp.loop_stop()
            tmp.disconnect()
        except Exception as e:
            log.warning("Purge: no se pudo conectar temporal: %s", e)
            return

        for topic in found:
            self.publish(topic, "", retain=True)
        log.info("Purge: %d entidades eliminadas del broker", len(found))

    def pub(self, device_token: str, device_name: str, field: str,
            value: Any, unit: str | None = None,
            device_class: str | None = None,
            icon: str | None = None) -> None:
        state_topic = self.announce(device_token, device_name, field, unit, device_class, icon)
        self.publish(state_topic, str(value))
        log.info("  MQTT %-45s = %s %s", state_topic, value, unit or "")


# ─────────────────────────────────────────────────────────────
#  Cliente suitch.network
# ─────────────────────────────────────────────────────────────

class SuitchClient:
    def __init__(self, email: str, password: str, initial_token: str = "", insecure_ssl: bool = False):
        self._email    = email
        self._password = password
        self._token    = initial_token
        self._ssl_ctx  = self._build_ssl_ctx(insecure_ssl)
        self._opener   = self._new_opener()

    @staticmethod
    def _build_ssl_ctx(insecure: bool) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
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
            import gzip; raw = gzip.decompress(raw)
        return raw

    def _base_headers(self) -> dict:
        return {"User-Agent": UA, "Accept": "application/json",
                "X-Requested-With": "XMLHttpRequest"}

    def _get_json(self, url: str, label: str) -> Any:
        req = urllib.request.Request(url, headers=self._base_headers())
        try:
            with self._opener.open(req, timeout=15) as r:
                body = self._read(r)
                return json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            log.warning("[GET %s] → %s: %s", label, e.code, body[:200])
            raise

    def _post_json(self, url: str, data: dict, label: str) -> Any:
        payload = json.dumps(data).encode("utf-8")
        headers = {**self._base_headers(), "Content-Type": "application/json"}
        if self._token:
            headers["X-CSRF-Token"] = self._token
        req = urllib.request.Request(url, data=payload, method="POST", headers=headers)
        try:
            with self._opener.open(req, timeout=15) as r:
                body = self._read(r)
                log.info("[%s] → %s", label, r.status)
                return json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            log.warning("[%s] → %s: %s", label, e.code, body[:200])
            return None

    def login(self) -> None:
        self._opener = self._new_opener()
        log.info("GET /auth/v2/verify.json (capturando token CSRF)")
        data  = self._get_json(f"{BASE_URL}/auth/v2/verify.json", "verify")
        token = (isinstance(data, dict) and (data.get("token") or data.get("authenticity_token"))) or ""
        if not token:
            raise RuntimeError("No se pudo obtener token de /auth/v2/verify.json")
        self._token = token
        save_token(token)
        log.info("Token de verify capturado: %s…", token[:16])
        resp = self._post_json(
            f"{BASE_URL}/auth/v2/login.json",
            {"email": self._email, "password": self._password,
             "authenticity_token": token, "utf8": "✓"},
            "login",
        )
        if resp is None or (isinstance(resp, dict) and (resp.get("errors") or resp.get("error"))):
            raise RuntimeError(f"Login rechazado: {resp}")
        if isinstance(resp, dict):
            nt = resp.get("token") or resp.get("authenticity_token") or resp.get("id_token")
            if nt and nt != self._token:
                self._token = nt; save_token(nt)
                log.info("Token rotado: %s…", str(nt)[:16])
        log.info("Login exitoso")

    def _ensure_get(self, url: str, label: str) -> Any:
        try:
            return self._get_json(url, label)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                log.info("Sesión expirada (%s) — re-login…", e.code)
                self.login()
                return self._get_json(url, label)
            raise

    def devices(self) -> list[dict]:
        data = self._ensure_get(f"{BASE_URL}/devices/v2/show.json", "devices")
        if isinstance(data, list): return data
        if isinstance(data, dict): return data.get("devices", []) or []
        return []

    def device_props(self, token: str) -> list[dict]:
        try:
            data = self._ensure_get(f"{BASE_URL}/devices/v2/{token}/props.json", f"props/{token}")
        except urllib.error.HTTPError:
            return []
        if isinstance(data, list): return data
        if isinstance(data, dict): return data.get("props", []) or []
        return []

    def device_battery(self, token: str) -> dict | None:
        try:
            data = self._ensure_get(f"{BASE_URL}/devices/v2/{token}/battery.json", f"battery/{token}")
        except urllib.error.HTTPError:
            return None
        return data if isinstance(data, dict) else None

    def device_soil(self, token: str) -> Any:
        for url in [f"{BASE_URL}/devices/v2/findmy/{token}/soil.json",
                    f"{BASE_URL}/devices/v2/{token}/soil.json"]:
            try:
                data = self._get_json(url, f"soil/{token}")
                if data is not None: return data
            except urllib.error.HTTPError:
                pass
        return None


# ─────────────────────────────────────────────────────────────
#  Publicar dispositivo
# ─────────────────────────────────────────────────────────────

def _pub_field(mqp: MQTTPublisher, token: str, name: str,
               field: str, raw_value: Any, raw_unit: str = "") -> None:
    """Publica un campo — separa XYZ si aplica, convierte Pa→hPa."""
    field_slug = _slug(field)

    # Separar XYZ
    if field_slug in _XYZ_FIELDS or any(x in field_slug for x in ("magnet", "accel", "gyro")):
        xyz = _parse_xyz(raw_value)
        if xyz:
            axes = ["x", "y", "z"]
            for ax, val in zip(axes, xyz):
                u, dc, icon = _unit_class_icon(f"{field_slug}_{ax}", raw_unit)
                mqp.pub(token, name, f"{field_slug}_{ax}", val, u, dc, icon)
            return

    # Convertir Pa → hPa
    value = raw_value
    unit  = raw_unit
    if "press" in field_slug or (isinstance(raw_unit, str) and raw_unit.strip().lower() in ("pa",)):
        hpa = _pa_to_hpa(raw_value)
        if hpa is not None:
            value = hpa
            unit  = "hPa"

    u, dc, icon = _unit_class_icon(field_slug, unit)
    mqp.pub(token, name, field_slug, value, u or unit or None, dc, icon)


def publish_device(client: SuitchClient, mqp: MQTTPublisher, dev: dict) -> None:
    token    = str(dev.get("token") or dev.get("uid") or dev.get("id") or "unknown")
    name     = str(dev.get("object") or dev.get("name") or dev.get("label") or token)
    dev_type = str(dev.get("type") or dev.get("device_type") or dev.get("object") or "")
    published = False

    # 1) Soil moisture
    if "soil" in dev_type.lower():
        raw = client.device_soil(token)
        if raw is not None:
            val = (raw if isinstance(raw, (int, float)) else
                   raw.get("value") if isinstance(raw, dict) else
                   (raw[0].get("value") if isinstance(raw, list) and raw else None))
            if val is not None:
                mqp.pub(token, name, "moisture", val, None, None, "mdi:water-percent")
                published = True

    # 2) Props reales
    for prop in client.device_props(token):
        label = str(prop.get("command") or prop.get("name") or prop.get("label") or "value")
        if label.lower() in _SKIP_PROPS: continue
        value = prop.get("value")
        unit  = str(prop.get("unit") or "")
        if value is None: continue
        _pub_field(mqp, token, name, label, value, unit)
        published = True

    # 3) Batería
    batt = client.device_battery(token)
    if isinstance(batt, dict):
        level = batt.get("level") or batt.get("percentage") or batt.get("value")
        if level is not None:
            mqp.pub(token, name, "battery", level, "%", "battery", "mdi:battery")
            published = True

    # 4) Campos numéricos del device object
    for field, value in dev.items():
        if field in _SKIP_FIELDS: continue
        if not isinstance(value, (int, float)) or isinstance(value, bool): continue
        _pub_field(mqp, token, name, field, value)
        published = True

    if not published:
        mqp.pub(token, name, "state", "online", None, None, "mdi:check-circle")


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main() -> None:
    cfg   = load_config()
    token = cfg["id_token"] or load_saved_token()

    client = SuitchClient(cfg["email"], cfg["password"], token, cfg["insecure_ssl"])
    mqp    = MQTTPublisher(cfg["mqtt_host"], cfg["mqtt_port"],
                           cfg["mqtt_user"], cfg["mqtt_password"])

    log.info("Addon arrancado — polling cada %ds", cfg["scan_interval"])
    mqp.purge_all()   # limpia entidades anteriores del broker
    client.login()

    while True:
        try:
            devs = client.devices()
            log.info("── %d dispositivo(s) ──", len(devs))
            for dev in devs:
                publish_device(client, mqp, dev)
        except Exception as e:
            log.warning("Error polling (%s) — re-login…", e)
            try:
                client.login()
            except Exception as le:
                log.error("Re-login fallido: %s", le)
        time.sleep(cfg["scan_interval"])


if __name__ == "__main__":
    main()
