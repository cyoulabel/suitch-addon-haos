#!/usr/bin/env python3
"""Suitch Network — Home Assistant Add-on v1.6.4"""

import json, logging, os, ssl, time, base64
import urllib.request, urllib.error, http.cookiejar
from typing import Any
import paho.mqtt.client as mqtt

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("suitch")

BASE_URL    = "https://suitch.network"
TOKEN_FILE  = "/data/id_token.txt"
DISC_PREFIX = "homeassistant"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ── Config ──────────────────────────────────────────────────
def load_config() -> dict:
    with open("/data/options.json", encoding="utf-8") as f:
        opts = json.load(f)
    e, p = opts.get("email","").strip(), opts.get("password","").strip()
    if not e or not p: raise ValueError("Email o password vacíos.")
    return {"email":e,"password":p,
            "scan_interval":int(opts.get("scan_interval",60)),
            "id_token":opts.get("id_token","").strip(),
            "insecure_ssl":bool(opts.get("insecure_ssl",False)),
            "mqtt_host":opts.get("mqtt_host","core-mosquitto"),
            "mqtt_port":int(opts.get("mqtt_port",1883)),
            "mqtt_user":opts.get("mqtt_user",""),
            "mqtt_password":opts.get("mqtt_password","")}

def load_saved_token() -> str:
    if os.path.exists(TOKEN_FILE):
        t = open(TOKEN_FILE).read().strip()
        if t: return t
    return ""

def save_token(t: str):
    try:
        open(TOKEN_FILE,"w").write(t)
    except OSError: pass

# ── Helpers ──────────────────────────────────────────────────
def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in s.lower()).strip("_")

def _unit_class_icon(field: str, unit: str = ""):
    f = f"{field} {unit}".lower()
    if any(x in f for x in ("moisture","hum","humidity","humedad")): return (unit or None),"humidity","mdi:water-percent"
    if any(x in f for x in ("temp","°c")):      return (unit or "°C"),"temperature","mdi:thermometer"
    if any(x in f for x in ("press","hpa")):    return "hPa","pressure","mdi:gauge"
    if any(x in f for x in ("volt",)):          return (unit or "V"),"voltage","mdi:lightning-bolt"
    if any(x in f for x in ("power","watt"," w ")): return (unit or "W"),"power","mdi:flash"
    if any(x in f for x in ("batt",)):          return (unit or "%"),"battery","mdi:battery"
    if "magnet" in f:                           return (unit or "µT"),None,"mdi:magnet"
    if "accel" in f:                            return (unit or "m/s²"),None,"mdi:axis-arrow"
    if "gyro" in f:                             return (unit or "°/s"),None,"mdi:rotate-3d-variant"
    return (unit or None),None,None

def _parse_xyz(v: str):
    try:
        p = [float(x.strip()) for x in str(v).split(",")]
        return tuple(p) if len(p)==3 else None
    except: return None

def _pa_to_hpa(v: Any):
    try:
        n = float(str(v).split()[0])
        return round(n/100,2) if n>10000 else n
    except: return None

def _parse_location(v: str) -> dict | None:
    try:
        d = json.loads(base64.b64decode(str(v).split()[0]+"=="))
        if "lat" in d and "lon" in d: return d
    except: pass
    return None

_XYZ = {"magnetometer","accelaration","acceleration","gyroscope"}

_SKIP_FIELDS = {
    "token","uid","id","object","name","label","type","device_type",
    "rig_id","rig_id_owner","rig_is_public","rig_likes","rig_connection_type",
    "id_owner","is_public","likes","connection_type",
    "created_at","updated_at","user_id","firmware","hardware","description",
    "notify_email","notify_twitter","notify_fbinbox","notify_telegram",
    "fav","location","bt_key",
}
_SKIP_PROPS = _SKIP_FIELDS | {"owner","public","connection"}

# ── MQTT ─────────────────────────────────────────────────────
class MQTTPublisher:
    def __init__(self, host, port, user, password):
        self._host, self._port = host, port
        self._user, self._password = user, password
        self._client = None
        self._connect()

    def _connect(self):
        c = mqtt.Client(client_id="suitch_addon", protocol=mqtt.MQTTv311)
        if self._user: c.username_pw_set(self._user, self._password)
        c.on_connect    = lambda *a: log.info("MQTT conectado (rc=%s)", a[3])
        c.on_disconnect = lambda *a: log.warning("MQTT desconectado (rc=%s)", a[2])
        try:
            c.connect(self._host, self._port, keepalive=60)
            c.loop_start(); time.sleep(1)
            self._client = c
            log.info("MQTT → %s:%s", self._host, self._port)
        except Exception as e:
            log.error("MQTT sin conexión: %s", e); self._client = None

    def publish(self, topic, payload, retain=False):
        if self._client is None: self._connect()
        if self._client: self._client.publish(topic, payload, qos=1, retain=retain)

    def purge_all(self):
        """Borra todos los topics suitch retenidos en el broker."""
        found = []
        def _on_msg(cl, ud, msg):
            if msg.payload and "/suitch_" in msg.topic:
                found.append(msg.topic)

        tmp = mqtt.Client(client_id="suitch_purge", protocol=mqtt.MQTTv311)
        if self._user: tmp.username_pw_set(self._user, self._password)
        tmp.on_message = _on_msg
        try:
            tmp.connect(self._host, self._port, keepalive=30)
            # Suscribir con wildcards válidos y filtrar por "suitch_" en el callback
            tmp.subscribe("homeassistant/sensor/+/config", qos=1)
            tmp.subscribe("homeassistant/device_tracker/+/config", qos=1)
            tmp.loop_start(); time.sleep(3)
            tmp.loop_stop(); tmp.disconnect()
        except Exception as e:
            log.warning("Purge error: %s", e); return

        for topic in found:
            self.publish(topic, "", retain=True)
        log.info("Purge: %d entidades Suitch eliminadas del broker", len(found))

    def _announce(self, token, name, field, unit, dc, icon):
        uid   = f"suitch_{token}_{field}"
        state = f"suitch/{token}/{field}/state"
        p = {"name":f"{name} {field}".strip(), "unique_id":uid,
             "state_topic":state,
             "device":{"identifiers":[f"suitch_{token}"],
                       "name":f"Suitch {name}",
                       "manufacturer":"Suitch","model":"suitch.network"}}
        if unit:  p["unit_of_measurement"] = unit
        if dc:    p["device_class"]        = dc
        if icon:  p["icon"]                = icon
        self.publish(f"{DISC_PREFIX}/sensor/{uid}/config", json.dumps(p), retain=True)
        return state

    def pub(self, token, name, field, value, unit=None, dc=None, icon=None):
        state = self._announce(token, name, field, unit, dc, icon)
        self.publish(state, str(value))
        log.info("  %-45s = %s %s", state, value, unit or "")

    def pub_tracker(self, token, name, loc):
        uid   = f"suitch_{token}_tracker"
        state = f"suitch/{token}/tracker/state"
        attrs = f"suitch/{token}/tracker/attributes"
        cfg = {"name":name, "unique_id":uid,
               "state_topic":state,
               "json_attributes_topic":attrs,
               "icon":"mdi:map-marker", "source_type":"gps",
               "payload_home":"home", "payload_not_home":"not_home",
               "device":{"identifiers":[f"suitch_{token}"],
                         "name":f"Suitch {name}",
                         "manufacturer":"Suitch","model":"suitch.network"}}
        self.publish(f"{DISC_PREFIX}/device_tracker/{uid}/config", json.dumps(cfg), retain=True)
        self.publish(state, "not_home", retain=True)
        self.publish(attrs, json.dumps({
            "latitude":loc["lat"], "longitude":loc["lon"],
            "gps_accuracy":int(loc.get("conf",50)), "source_type":"gps"}), retain=True)
        log.info("  TRACKER suitch/%s lat=%.4f lon=%.4f", token, loc["lat"], loc["lon"])

# ── Suitch HTTP client ────────────────────────────────────────
class SuitchClient:
    def __init__(self, email, password, token="", insecure=False):
        self._email, self._password, self._token = email, password, token
        ctx = ssl.create_default_context()
        if insecure: ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        self._ctx = ctx; self._opener = self._new_opener()

    def _new_opener(self):
        jar = http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPSHandler(context=self._ctx))

    def _read(self, r):
        raw = r.read()
        if r.headers.get("Content-Encoding")=="gzip":
            import gzip; raw=gzip.decompress(raw)
        return raw

    def _hdr(self): return {"User-Agent":UA,"Accept":"application/json","X-Requested-With":"XMLHttpRequest"}

    def _get(self, url, lbl):
        req = urllib.request.Request(url, headers=self._hdr())
        with self._opener.open(req, timeout=15) as r:
            body = self._read(r)
            return json.loads(body) if body else None

    def _post(self, url, data, lbl):
        h = {**self._hdr(),"Content-Type":"application/json"}
        if self._token: h["X-CSRF-Token"]=self._token
        req = urllib.request.Request(url, json.dumps(data).encode(), method="POST", headers=h)
        try:
            with self._opener.open(req, timeout=15) as r:
                body=self._read(r); log.info("[%s] → %s",lbl,r.status)
                return json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            log.warning("[%s] → %s: %s",lbl,e.code,e.read().decode()[:200]); return None

    def login(self):
        self._opener = self._new_opener()
        log.info("GET /auth/v2/verify.json (capturando token CSRF)")
        d = self._get(f"{BASE_URL}/auth/v2/verify.json","verify")
        t = isinstance(d,dict) and (d.get("token") or d.get("authenticity_token")) or ""
        if not t: raise RuntimeError("No token de verify.json")
        self._token=t; save_token(t); log.info("Token de verify capturado: %s…",t[:16])
        r = self._post(f"{BASE_URL}/auth/v2/login.json",
            {"email":self._email,"password":self._password,"authenticity_token":t,"utf8":"✓"},"login")
        if r is None or (isinstance(r,dict) and (r.get("error") or r.get("errors"))):
            raise RuntimeError(f"Login rechazado: {r}")
        if isinstance(r,dict):
            nt=r.get("token") or r.get("authenticity_token") or r.get("id_token")
            if nt and nt!=self._token: self._token=nt; save_token(nt); log.info("Token rotado: %s…",str(nt)[:16])
        log.info("Login exitoso")

    def _ensure(self, url, lbl):
        try: return self._get(url,lbl)
        except urllib.error.HTTPError as e:
            if e.code in (401,403): self.login(); return self._get(url,lbl)
            raise

    def devices(self):
        d=self._ensure(f"{BASE_URL}/devices/v2/show.json","devices")
        return d if isinstance(d,list) else (d.get("devices",[]) if isinstance(d,dict) else [])

    def props(self, token):
        try:
            d=self._ensure(f"{BASE_URL}/devices/v2/{token}/props.json",f"props/{token}")
            return d if isinstance(d,list) else (d.get("props",[]) if isinstance(d,dict) else [])
        except: return []

    def battery(self, token):
        try:
            d=self._ensure(f"{BASE_URL}/devices/v2/{token}/battery.json",f"bat/{token}")
            return d if isinstance(d,dict) else None
        except: return None

    def soil(self, token):
        for url in [f"{BASE_URL}/devices/v2/findmy/{token}/soil.json",
                    f"{BASE_URL}/devices/v2/{token}/soil.json"]:
            try:
                d=self._get(url,f"soil/{token}")
                if d is not None: return d
            except urllib.error.HTTPError: pass
        return None

# ── Publish ──────────────────────────────────────────────────
def _pub_field(mqp, token, name, field, raw_val, raw_unit=""):
    fs = _slug(field)
    if fs in _XYZ or any(x in fs for x in ("magnet","accel","gyro")):
        xyz = _parse_xyz(raw_val)
        if xyz:
            for ax,v in zip(("x","y","z"),xyz):
                u,dc,icon = _unit_class_icon(f"{fs}_{ax}",raw_unit)
                mqp.pub(token,name,f"{fs}_{ax}",v,u,dc,icon)
            return
    val,unit = raw_val,raw_unit
    if "press" in fs or (isinstance(raw_unit,str) and raw_unit.strip().lower()=="pa"):
        hpa=_pa_to_hpa(raw_val)
        if hpa is not None: val,unit=hpa,"hPa"
    u,dc,icon = _unit_class_icon(fs,unit)
    mqp.pub(token,name,fs,val,u or unit or None,dc,icon)

def publish_device(client: SuitchClient, mqp: MQTTPublisher, dev: dict):
    token   = str(dev.get("token") or dev.get("uid") or dev.get("id") or "unknown")
    name    = str(dev.get("object") or dev.get("name") or dev.get("label") or token)
    dtype   = str(dev.get("type") or dev.get("device_type") or dev.get("object") or "")
    published = False

    # Soil
    if "soil" in dtype.lower():
        raw = client.soil(token)
        if raw is not None:
            val = (raw if isinstance(raw,(int,float)) else
                   raw.get("value") if isinstance(raw,dict) else
                   (raw[0].get("value") if isinstance(raw,list) and raw else None))
            if val is not None:
                mqp.pub(token,name,"moisture",val,None,None,"mdi:water-percent")
                published=True

    # Props
    for prop in client.props(token):
        lbl = str(prop.get("command") or prop.get("name") or prop.get("label") or "value")
        if lbl.lower() in _SKIP_PROPS:
            if lbl.lower() in ("location","bt_key"):
                loc=_parse_location(str(prop.get("value") or ""))
                if loc: mqp.pub_tracker(token,name,loc); published=True
            continue
        val=prop.get("value"); unit=str(prop.get("unit") or "")
        if val is None: continue
        _pub_field(mqp,token,name,lbl,val,unit); published=True

    # Battery
    batt=client.battery(token)
    if isinstance(batt,dict):
        lvl=batt.get("level") or batt.get("percentage") or batt.get("value")
        if lvl is not None: mqp.pub(token,name,"battery",lvl,"%","battery","mdi:battery"); published=True

    # Device fields
    for field,value in dev.items():
        if field in _SKIP_FIELDS:
            if field in ("location","bt_key") and value:
                loc=_parse_location(str(value))
                if loc: mqp.pub_tracker(token,name,loc); published=True
            continue
        if not isinstance(value,(int,float)) or isinstance(value,bool): continue
        _pub_field(mqp,token,name,field,value); published=True

    if not published:
        mqp.pub(token,name,"state","online",None,None,"mdi:check-circle")

# ── Main ─────────────────────────────────────────────────────
def main():
    cfg   = load_config()
    token = cfg["id_token"] or load_saved_token()
    client = SuitchClient(cfg["email"],cfg["password"],token,cfg["insecure_ssl"])
    mqp    = MQTTPublisher(cfg["mqtt_host"],cfg["mqtt_port"],cfg["mqtt_user"],cfg["mqtt_password"])

    log.info("Addon arrancado — polling cada %ds", cfg["scan_interval"])
    mqp.purge_all()
    client.login()

    while True:
        try:
            devs = client.devices()
            log.info("── %d dispositivo(s) ──", len(devs))
            for dev in devs:
                publish_device(client, mqp, dev)
        except Exception as e:
            log.warning("Error polling (%s) — re-login…", e)
            try: client.login()
            except Exception as le: log.error("Re-login fallido: %s", le)
        time.sleep(cfg["scan_interval"])

if __name__ == "__main__":
    main()
