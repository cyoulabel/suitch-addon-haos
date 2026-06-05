# Suitch Network — Home Assistant Add-on

Add-on para conectar Home Assistant con [suitch.network](https://suitch.network).

## Instalación

1. **Supervisor → Add-on Store → ⋮ → Repositories**
2. Agrega: `https://github.com/cyoulabel/addon-suitch-network`
3. Busca **"Suitch Network"** e instala
4. En **Configuration** pon tu email, password y scan_interval
5. **Start**

## Entidades que crea

- `sensor.suitch_<dispositivo>_humidity` → Humedad (%)
- `sensor.suitch_<dispositivo>_temperature` → Temperatura (°C)
- `sensor.suitch_<dispositivo>_voltage` → Voltaje (V)
