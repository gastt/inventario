# Inventario IT (server) — Flask + SQLite (modo red)

## Qué incluye (MVP)
- Login + usuarios (admin).
- Base central SQLite (`inventario.sqlite3`) con WAL.
- Paneles: Stock, Asignar, Reasignar, Reparaciones, Bajas, Consultas.
- Modal con detalle obligatorio para: baja, reparaciones, retornos, reactivar.
- Exportación CSV: `/export/productos.csv`, `/export/unidades.csv`, `/export/historial.csv`

Usuario inicial: `admin` / `admin` (cambiar en panel Usuarios).

## Instalación
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Abrir: http://localhost:5000

## En red
Ejecutá en la PC “servidor” y desde otras PCs usá: `http://IP_DEL_SERVIDOR:5000`.
Asegurate de permitir el puerto en el firewall.

## Variables útiles
- `INVENTARIO_SECRET_KEY`: clave de sesión (poné una larga).
- `INVENTARIO_DB_PATH`: ruta a la DB.
- `PORT`: puerto (default 5000).
