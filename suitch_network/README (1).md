# Suitch Network Add-on

Conecta Home Assistant con [suitch.network](https://suitch.network) y publica automáticamente cada sensor como entidad en HA.

## Configuración

| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `email` | Tu cuenta de suitch.network | tu@email.com |
| `password` | Tu contraseña | ••••••• |
| `scan_interval` | Segundos entre cada polling | 60 |

## Entidades creadas

El addon detecta automáticamente los campos numéricos de cada dispositivo:

- `sensor.suitch_<nombre>_humidity` — Humedad (%)
- `sensor.suitch_<nombre>_temperature` — Temperatura (°C)
- `sensor.suitch_<nombre>_voltage` — Voltaje (V)

## Comunicación

- **suitch.network** → HTTPS puerto 443 (salida)
- **HA Supervisor API** → HTTP interno, sin puerto expuesto
