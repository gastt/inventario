from __future__ import annotations
import os
import re
import sqlite3
from functools import wraps
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo
from typing import Optional, Dict

from flask import Flask, g, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.security import generate_password_hash, check_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("INVENTARIO_DB_PATH", os.path.join(APP_DIR, "inventario.sqlite3"))


def norm_date_range(date_from: str | None, date_to: str | None):
    """Accept YYYY-MM-DD and return ISO range strings for lexicographic compare."""
    df = (date_from or "").strip()
    dt = (date_to or "").strip()
    iso_from = None
    iso_to = None
    if df:
        iso_from = df + "T00:00:00"
    if dt:
        iso_to = dt + "T23:59:59"
    return iso_from, iso_to

def utc_now_iso() -> str:
    # Local time for Montevideo (America/Montevideo, GMT-3)
    return datetime.now(ZoneInfo("America/Montevideo")).isoformat(timespec="seconds")

def now_iso() -> str:
    return utc_now_iso()

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
        ensure_schema_migrations(g.db)
    return g.db


def ensure_schema_migrations(db):
    # Migraciones simples para bases existentes
    try:
        cols = [r["name"] for r in db.execute("PRAGMA table_info(products)").fetchall()]
        if "proveedor_id" not in cols:
            db.execute("ALTER TABLE products ADD COLUMN proveedor_id INTEGER")
            db.commit()
    except Exception:
        pass

    try:
        cols_u = [r["name"] for r in db.execute("PRAGMA table_info(units)").fetchall()]
        if "purchase_provider_id" not in cols_u:
            db.execute("ALTER TABLE units ADD COLUMN purchase_provider_id INTEGER")
            db.commit()
    except Exception:
        pass



    # Ajuste de unicidad: permitir mismo barcode en distintos proveedores
    try:
        db.execute("DROP INDEX IF EXISTS idx_products_barcode")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_products_barcode_provider ON products(barcode, IFNULL(proveedor_id,0)) WHERE barcode IS NOT NULL AND barcode != ''")
        db.commit()
    except Exception:
        pass
def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA journal_mode=WAL;")
    db.execute("PRAGMA foreign_keys=ON;")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      barcode TEXT,
      descripcion TEXT NOT NULL,
      tipo TEXT NOT NULL,
      marca TEXT NOT NULL,
      modelo TEXT NOT NULL,
      proveedor_id INTEGER REFERENCES providers(id),
      created_at TEXT NOT NULL
    );

    DROP INDEX IF EXISTS idx_products_barcode;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_products_barcode_provider ON products(barcode, IFNULL(proveedor_id,0)) WHERE barcode IS NOT NULL AND barcode != '';

    CREATE TABLE IF NOT EXISTS units (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
      serial TEXT,
      status TEXT NOT NULL CHECK(status IN ('IN_STOCK','ASSIGNED','IN_REPAIR','RETIRED')),
      warranty_until TEXT,
      purchase_provider_id INTEGER REFERENCES providers(id),
      sucursal TEXT,
      area TEXT,
      persona TEXT,
      last_sucursal TEXT,
      last_area TEXT,
      last_persona TEXT,
      pc_name TEXT,
      last_pc_name TEXT,
      inventory_number TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_units_product_serial ON units(product_id, serial) WHERE serial IS NOT NULL AND serial != '';

    


    CREATE TABLE IF NOT EXISTS providers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL UNIQUE,
      direccion TEXT,
      contacto TEXT,
      created_at TEXT NOT NULL
    );

CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      unit_id INTEGER NOT NULL REFERENCES units(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
      type TEXT NOT NULL,
      from_status TEXT,
      to_status TEXT,
      from_sucursal TEXT, from_area TEXT, from_persona TEXT,
      to_sucursal TEXT, to_area TEXT, to_persona TEXT,
      proveedor TEXT,
      detalle TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    """)
    row = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    if row[0] == 0:
        db.execute(
            "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,?,?)",
            ("admin", generate_password_hash("admin"), 1, utc_now_iso()),
        )
        print(">>> Usuario inicial creado: admin / admin (cambiá la contraseña en Usuarios)")
    
    # Migración suave: agregar proveedor_id a products si no existe
    try:
        db.execute("ALTER TABLE products ADD COLUMN proveedor_id INTEGER")
    except Exception:
        pass

    db.commit()
    db.close()

def close_db(e=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            flash("Acceso denegado (admin).", "error")
            return redirect(url_for("stock"))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

def add_history(unit_id:int, type_:str, detalle:str,
                from_status:Optional[str]=None, to_status:Optional[str]=None,
                from_loc:Optional[Dict[str,str]]=None, to_loc:Optional[Dict[str,str]]=None,
                proveedor:Optional[str]=None) -> None:
    db = get_db()
    u = current_user()
    assert u is not None
    fl = from_loc or {}
    tl = to_loc or {}
    db.execute("""
      INSERT INTO history(unit_id,user_id,type,from_status,to_status,
        from_sucursal,from_area,from_persona,to_sucursal,to_area,to_persona,
        proveedor,detalle,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
      unit_id, u["id"], type_, from_status, to_status,
      fl.get("sucursal"), fl.get("area"), fl.get("persona"),
      tl.get("sucursal"), tl.get("area"), tl.get("persona"),
      proveedor, detalle, utc_now_iso()
    ))

def unit_row(unit_id:int):
    db = get_db()
    r = db.execute("""
      SELECT u.*, p.descripcion, p.tipo, p.marca, p.modelo, p.barcode
      FROM units u JOIN products p ON p.id = u.product_id
      WHERE u.id = ?
    """,(unit_id,)).fetchone()
    if r is None:
        raise ValueError("Unidad no encontrada.")
    return r

def parse_date(s: str) -> Optional[str]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        date.fromisoformat(s)
        return s
    except Exception:
        return None

app = Flask(__name__)
app.secret_key = os.environ.get("INVENTARIO_SECRET_KEY", "cambia-esto-por-una-clave-larga")

@app.before_request
def _fk_on():
    db = get_db()
    db.execute("PRAGMA foreign_keys=ON;")

@app.teardown_appcontext
def _close(e=None):
    close_db(e)

@app.context_processor
def inject_globals():
    return {"me": current_user()}

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("stock"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if u and check_password_hash(u["password_hash"], password):
            session["user_id"] = u["id"]
            session["username"] = u["username"]
            session["is_admin"] = bool(u["is_admin"])
            return redirect(request.args.get("next") or url_for("stock"))
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/stock")
@login_required
def stock():
    q = (request.args.get("q") or "").strip().lower()
    db = get_db()
    products = db.execute("""
      SELECT p.*,
        SUM(CASE WHEN u.status='IN_STOCK' THEN 1 ELSE 0 END) AS in_stock,
        SUM(CASE WHEN u.status='ASSIGNED' THEN 1 ELSE 0 END) AS assigned,
        SUM(CASE WHEN u.status='IN_REPAIR' THEN 1 ELSE 0 END) AS in_repair,
        SUM(CASE WHEN u.status='RETIRED' THEN 1 ELSE 0 END) AS retired
      FROM products p
      LEFT JOIN units u ON u.product_id = p.id
      GROUP BY p.id
      ORDER BY p.descripcion COLLATE NOCASE
    """).fetchall()
    if q:
        products = [p for p in products if q in f"{p['descripcion']} {p['tipo']} {p['marca']} {p['modelo']} {p['barcode'] or ''}".lower()]
    providers = db.execute("SELECT id,nombre FROM providers ORDER BY nombre COLLATE NOCASE").fetchall()
    
    # distinct values for datalist suggestions (normalize)
    tipos = [r["tipo"] for r in db.execute("SELECT DISTINCT tipo FROM products WHERE tipo IS NOT NULL AND TRIM(tipo)<>'' ORDER BY tipo COLLATE NOCASE").fetchall()]
    descripciones = [r["descripcion"] for r in db.execute("SELECT DISTINCT descripcion FROM products WHERE descripcion IS NOT NULL AND TRIM(descripcion)<>'' ORDER BY descripcion COLLATE NOCASE").fetchall()]
    marcas = [r["marca"] for r in db.execute("SELECT DISTINCT marca FROM products WHERE marca IS NOT NULL AND TRIM(marca)<>'' ORDER BY marca COLLATE NOCASE").fetchall()]
    modelos = [r["modelo"] for r in db.execute("SELECT DISTINCT modelo FROM products WHERE modelo IS NOT NULL AND TRIM(modelo)<>'' ORDER BY modelo COLLATE NOCASE").fetchall()]

    return render_template("stock.html", products=products, q=q, providers=providers, tipos=tipos, descripciones=descripciones, marcas=marcas, modelos=modelos)


@app.route("/stock_all")
@login_required
def stock_all():
    q = (request.args.get("q") or "").strip().lower()
    db = get_db()

    if q:
        like = f"%{q}%"
        products = db.execute(
            """
            SELECT p.*,
              SUM(CASE WHEN u.status='IN_STOCK' THEN 1 ELSE 0 END) AS in_stock,
              SUM(CASE WHEN u.status='ASSIGNED' THEN 1 ELSE 0 END) AS assigned,
              SUM(CASE WHEN u.status='IN_REPAIR' THEN 1 ELSE 0 END) AS in_repair,
              SUM(CASE WHEN u.status='RETIRED' THEN 1 ELSE 0 END) AS retired
            FROM products p
            LEFT JOIN units u ON u.product_id = p.id
            WHERE
              LOWER(p.descripcion) LIKE ?
              OR LOWER(p.tipo) LIKE ?
              OR LOWER(p.marca) LIKE ?
              OR LOWER(p.modelo) LIKE ?
              OR LOWER(COALESCE(p.barcode,'')) LIKE ?
              OR EXISTS (
                    SELECT 1 FROM units uu
                    WHERE uu.product_id = p.id
                      AND LOWER(COALESCE(uu.serial,'')) LIKE ?
              )
            GROUP BY p.id
            ORDER BY p.descripcion COLLATE NOCASE
            """,
            (like, like, like, like, like, like),
        ).fetchall()
    else:
        products = db.execute(
            """
            SELECT p.*,
              SUM(CASE WHEN u.status='IN_STOCK' THEN 1 ELSE 0 END) AS in_stock,
              SUM(CASE WHEN u.status='ASSIGNED' THEN 1 ELSE 0 END) AS assigned,
              SUM(CASE WHEN u.status='IN_REPAIR' THEN 1 ELSE 0 END) AS in_repair,
              SUM(CASE WHEN u.status='RETIRED' THEN 1 ELSE 0 END) AS retired
            FROM products p
            LEFT JOIN units u ON u.product_id = p.id
            GROUP BY p.id
            ORDER BY p.descripcion COLLATE NOCASE
            """
        ).fetchall()

    return render_template("stock_all.html", products=products, q=q)

@app.route("/assign")
@login_required
def assign_page():
    db = get_db()
    products = db.execute("""
      SELECT p.*,
        SUM(CASE WHEN u.status='IN_STOCK' THEN 1 ELSE 0 END) AS in_stock
      FROM products p
      LEFT JOIN units u ON u.product_id = p.id
      GROUP BY p.id
      HAVING in_stock > 0
      ORDER BY p.descripcion COLLATE NOCASE
    """).fetchall()
    return render_template("assign.html", products=products)


@app.route("/reassign")
@login_required
def reassign_page():
    # Mostrar últimos 30 por defecto; si hay filtro, mostrar todo
    has_search = bool((request.args.get('q') or '').strip())
    q = (request.args.get("q") or "").strip().lower()
    db = get_db()
    limit_sql = 4000 if has_search else 30
    units = db.execute("""
      SELECT u.*, p.descripcion, p.tipo, p.marca, p.modelo,
             (
               SELECT h.created_at
               FROM history h
               WHERE h.unit_id = u.id AND h.type IN ('ASSIGN','REASSIGN')
               ORDER BY h.created_at DESC
               LIMIT 1
             ) AS last_assign_at
      FROM units u
      JOIN products p ON p.id = u.product_id
      WHERE u.status='ASSIGNED'
      ORDER BY (last_assign_at IS NULL) ASC, last_assign_at DESC, u.id DESC
      LIMIT ?
    """, (limit_sql,)).fetchall()
    if q:
        units = [u for u in units if q in f"{u['serial'] or ''} {u['descripcion']} {u['marca']} {u['modelo']} {u['tipo']} {u['sucursal'] or ''} {u['area'] or ''} {u['persona'] or ''}".lower()]
    return render_template("reassign.html", units=units, q=q)


@app.route("/assigned")
@login_required
def assigned_page():
    q = (request.args.get("q") or "").strip().lower()
    tipo = (request.args.get("tipo") or "").strip()
    marca = (request.args.get("marca") or "").strip().lower()
    modelo = (request.args.get("modelo") or "").strip().lower()
    pc = (request.args.get("pc") or "").strip().lower()  # nombre PC
    pc_name_filter = pc
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()
    iso_from, iso_to = norm_date_range(date_from, date_to)

    has_filters = any([
        bool(q), bool(tipo), bool(marca), bool(modelo), bool(pc_name_filter), bool(date_from), bool(date_to)
    ])

    db = get_db()
    tipos = [r["tipo"] for r in db.execute("SELECT DISTINCT tipo FROM products ORDER BY tipo COLLATE NOCASE").fetchall()]

    sql = """
      SELECT u.*, p.descripcion, p.tipo, p.marca, p.modelo,
        (
          SELECT h.created_at
          FROM history h
          WHERE h.unit_id=u.id AND h.type IN ('ASSIGN','REASSIGN','RESTORE') AND h.to_status='ASSIGNED'
          ORDER BY h.created_at DESC
          LIMIT 1
        ) AS assigned_at
      FROM units u
      JOIN products p ON p.id=u.product_id
      WHERE u.status='ASSIGNED'
    """
    params = []
    if tipo:
        sql += " AND p.tipo = ?"
        params.append(tipo)
    if iso_from:
        sql += " AND assigned_at >= ?"
        params.append(iso_from)
    if iso_to:
        sql += " AND assigned_at <= ?"
        params.append(iso_to)

        sql += " ORDER BY (assigned_at IS NULL) ASC, assigned_at DESC, p.descripcion COLLATE NOCASE, COALESCE(u.serial,'')"
    rows = db.execute(sql, params).fetchall()

    if not has_filters:
        rows = rows[:30]

    if q:
        rows = [r for r in rows if q in f"{r['descripcion']} {r['serial'] or ''} {r['pc_name'] or ''} {r['sucursal'] or ''} {r['area'] or ''} {r['persona'] or ''}".lower()]
    if marca:
        rows = [r for r in rows if marca in f"{r['marca'] or ''}".lower()]
    if modelo:
        rows = [r for r in rows if modelo in f"{r['modelo'] or ''}".lower()]
    if pc_name_filter:
        rows = [r for r in rows if pc_name_filter in f"{r['pc_name'] or ''}".lower()]

    return render_template("assigned.html", rows=rows, tipos=tipos, q=q, tipo=tipo, marca=marca, modelo=modelo, pc=pc_name_filter, date_from=date_from, date_to=date_to)



@app.post("/api/provider_update")
@login_required
def api_provider_update():
    db = get_db()
    user = current_user()
    if not user or not user["is_admin"] :
        return jsonify({"ok": False, "error": "Solo admin."}), 403
    try:
        provider_id = int((request.form.get("provider_id") or "0").strip() or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "ID inválido."}), 400
    nombre = (request.form.get("nombre") or "").strip()
    direccion = (request.form.get("direccion") or "").strip() or None
    contacto = (request.form.get("contacto") or "").strip() or None
    if provider_id <= 0 or not nombre:
        return jsonify({"ok": False, "error": "Datos inválidos."}), 400
    try:
        db.execute("UPDATE providers SET nombre=?, direccion=?, contacto=? WHERE id=?",
                   (nombre, direccion, contacto, provider_id))
        db.commit()
    except Exception as e:
        return jsonify({"ok": False, "error": "No se pudo actualizar: " + str(e)}), 400
    return jsonify({"ok": True})
@app.route("/providers")
@login_required
def providers_page():
    q = (request.args.get("q") or "").strip().lower()
    db = get_db()
    rows = db.execute("SELECT * FROM providers ORDER BY nombre COLLATE NOCASE").fetchall()
    if q:
        rows = [r for r in rows if q in f"{r['nombre']} {r['direccion'] or ''} {r['contacto'] or ''}".lower()]
    return render_template("providers.html", rows=rows, q=q)

@app.post("/api/providers/create")
@login_required
def api_provider_create():
    db = get_db()
    nombre = (request.form.get("nombre") or "").strip()
    direccion = (request.form.get("direccion") or "").strip() or None
    contacto = (request.form.get("contacto") or "").strip() or None
    if not nombre:
        return jsonify({"ok": False, "error": "Nombre obligatorio."}), 400
    try:
        db.execute("INSERT INTO providers(nombre,direccion,contacto,created_at) VALUES(?,?,?,?)",
                   (nombre, direccion, contacto, utc_now_iso()))
        db.commit()
    except Exception:
        return jsonify({"ok": False, "error": "No se pudo guardar (¿nombre duplicado?)."}), 400
    return jsonify({"ok": True})

@app.post("/api/providers/delete")
@login_required
def api_provider_delete():
    user = current_user()
    if not user or not user["is_admin"] :
        return jsonify({"ok": False, "error": "Solo admin."}), 403
    db = get_db()
    try:
        pid = int((request.form.get("id") or "0").strip() or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "ID inválido."}), 400
    if pid <= 0:
        return jsonify({"ok": False, "error": "ID inválido."}), 400

    # Evitar eliminar si hay artículos asociados
    try:
        cnt = db.execute("SELECT COUNT(*) AS c FROM products WHERE proveedor_id=?", (pid,)).fetchone()
        if cnt and cnt["c"] > 0:
            return jsonify({"ok": False, "error": "No se puede eliminar: hay artículos asociados."}), 400
    except Exception:
        pass
    try:
        db.execute("DELETE FROM providers WHERE id=?", (pid,))
        db.commit()
    except Exception as e:
        return jsonify({"ok": False, "error": "No se pudo eliminar: " + str(e)}), 400
    return jsonify({"ok": True})



@app.get("/api/product_by_barcode")
@login_required
def api_product_by_barcode():
    barcode = (request.args.get("barcode") or "").strip()
    if not barcode:
        return jsonify({"ok": False, "error": "Barcode vacío."}), 400
    db = get_db()
    rows = db.execute(
        """SELECT p.id, p.barcode, p.descripcion, p.tipo, p.marca, p.modelo, p.proveedor_id,
                  COALESCE(pr.nombre,'') AS proveedor_nombre
           FROM products p
           LEFT JOIN providers pr ON pr.id = p.proveedor_id
           WHERE p.barcode=?
           ORDER BY p.id ASC""",
        (barcode,),
    ).fetchall()
    if not rows:
        return jsonify({"ok": True, "found": False, "matches": []})
    return jsonify({"ok": True, "found": True, "matches": [dict(r) for r in rows]})


@app.get("/api/providers/list")
@login_required
def api_providers_list():
    db = get_db()
    rows = db.execute("SELECT id, nombre FROM providers ORDER BY nombre COLLATE NOCASE").fetchall()
    return jsonify({"ok": True, "rows": [dict(r) for r in rows], "providers": [dict(r) for r in rows]})


@app.route("/repairs_history")
@login_required
def repairs_history_page():
    # Mostrar últimos 30 por defecto; si hay filtros, mostrar todo
    has_search = any((request.args.get(k) or '').strip() for k in ['q','serial','barcode','proveedor','motivo','desde','hasta','from','to','fecha'])
    q = (request.args.get("q") or "").strip().lower()
    tipo = (request.args.get("tipo") or "").strip()
    marca = (request.args.get("marca") or "").strip().lower()
    modelo = (request.args.get("modelo") or "").strip().lower()
    pc = (request.args.get("pc") or "").strip().lower()  # nombre PC
    pc_name_filter = pc
    proveedor = (request.args.get("proveedor") or "").strip().lower()
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()
    iso_from, iso_to = norm_date_range(date_from, date_to)

    db = get_db()
    limit_sql = 4000 if has_search else 30
    tipos = [r["tipo"] for r in db.execute("SELECT DISTINCT tipo FROM products ORDER BY tipo COLLATE NOCASE").fetchall()]
    provs = [r["nombre"] for r in db.execute("SELECT nombre FROM providers ORDER BY nombre COLLATE NOCASE").fetchall()]

    sql = """
      SELECT h.*, u.id AS unit_id, u.serial,
             p.descripcion, p.tipo, p.marca, p.modelo, p.barcode
      FROM history h
      JOIN units u ON u.id = h.unit_id
      JOIN products p ON p.id = u.product_id
      WHERE h.type IN ('REPAIR_SEND','REPAIR_RETURN')
    """
    params = []
    if tipo:
        sql += " AND p.tipo = ?"
        params.append(tipo)
    if iso_from:
        sql += " AND h.created_at >= ?"
        params.append(iso_from)
    if iso_to:
        sql += " AND h.created_at <= ?"
        params.append(iso_to)

    sql += " ORDER BY h.created_at DESC LIMIT 2000"
    rows = db.execute(sql, params).fetchall()

    # filtros en python para inputs libres
    if q:
        rows = [r for r in rows if q in f"{r['descripcion']} {r['serial'] or ''} {r['barcode'] or ''}".lower()]
    if marca:
        rows = [r for r in rows if marca in f"{r['marca'] or ''}".lower()]
    if modelo:
        rows = [r for r in rows if modelo in f"{r['modelo'] or ''}".lower()]
    if proveedor:
        rows = [r for r in rows if proveedor in f"{r['proveedor'] or ''}".lower()]

    return render_template("repairs_history.html", rows=rows, tipos=tipos, provs=provs,
                           q=q, tipo=tipo, marca=marca, modelo=modelo, proveedor=proveedor,
                           date_from=date_from, date_to=date_to)


@app.route("/repairs")
@login_required
def repairs_page():
    q1 = (request.args.get("q1") or "").strip().lower()  # buscar elegibles
    q2 = (request.args.get("q2") or "").strip().lower()  # buscar historial
    scope = request.args.get("scope") or "ANY"
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()
    iso_from, iso_to = norm_date_range(date_from, date_to)

    db = get_db()

    if scope == "IN_STOCK":
        eligible = ("IN_STOCK",)
    elif scope == "ASSIGNED":
        eligible = ("ASSIGNED",)
    else:
        eligible = ("IN_STOCK", "ASSIGNED")

    # Mostrar elegibles SOLO cuando hay búsqueda (q1)
    send = []
    if q1:
        send = db.execute(f"""
          SELECT u.*, p.descripcion, p.tipo, p.marca, p.modelo
          FROM units u JOIN products p ON p.id=u.product_id
          WHERE u.status IN ({','.join(['?']*len(eligible))})
          ORDER BY p.descripcion COLLATE NOCASE, COALESCE(u.serial,'')
        """, eligible).fetchall()
        send = [u for u in send if q1 in f"{u['serial'] or ''} {u['descripcion']} {u['marca']} {u['modelo']} {u['tipo']} {u['sucursal'] or ''} {u['area'] or ''} {u['persona'] or ''}".lower()]

    # En reparación (incluye motivo y fecha de envío)
    inrep_sql = """
      SELECT u.*, p.descripcion, p.tipo, p.marca, p.modelo,
        (
          SELECT h.detalle
          FROM history h
          WHERE h.unit_id = u.id AND h.type = 'REPAIR_SEND'
          ORDER BY h.created_at DESC
          LIMIT 1
        ) AS repair_motivo,
        (
          SELECT h.proveedor
          FROM history h
          WHERE h.unit_id = u.id AND h.type = 'REPAIR_SEND'
          ORDER BY h.created_at DESC
          LIMIT 1
        ) AS repair_proveedor,
        (
          SELECT h.created_at
          FROM history h
          WHERE h.unit_id = u.id AND h.type = 'REPAIR_SEND'
          ORDER BY h.created_at DESC
          LIMIT 1
        ) AS repair_sent_at
      FROM units u JOIN products p ON p.id=u.product_id
      WHERE u.status='IN_REPAIR'
    """
    params = []
    if iso_from:
        inrep_sql += " AND (SELECT h.created_at FROM history h WHERE h.unit_id = u.id AND h.type = 'REPAIR_SEND' ORDER BY h.created_at DESC LIMIT 1) >= ?"
        params.append(iso_from)
    if iso_to:
        inrep_sql += " AND (SELECT h.created_at FROM history h WHERE h.unit_id = u.id AND h.type = 'REPAIR_SEND' ORDER BY h.created_at DESC LIMIT 1) <= ?"
        params.append(iso_to)
    inrep_sql += " ORDER BY p.descripcion COLLATE NOCASE, COALESCE(u.serial,'')"
    inrep = db.execute(inrep_sql, params).fetchall()
    # Aplicar filtro de texto a "En reparación" (q2)
    if q2:
        inrep = [u for u in inrep if q2 in f"{u['serial'] or ''} {u['descripcion']} {u['marca']} {u['modelo']} {u['tipo']} {u['sucursal'] or ''} {u['area'] or ''} {u['persona'] or ''} {u['repair_proveedor'] or ''} {u['repair_motivo'] or ''}".lower()]


    # Historial de reparaciones (panel)
    hist_sql = """
      SELECT h.*, u.serial, p.descripcion, p.marca, p.modelo, us.username
      FROM history h
      JOIN units u ON u.id=h.unit_id
      JOIN products p ON p.id=u.product_id
      JOIN users us ON us.id=h.user_id
      WHERE h.type IN ('REPAIR_SEND','REPAIR_RETURN')
    """
    hparams = []
    if q2:
        hist_sql += " AND (LOWER(COALESCE(u.serial,'')) LIKE ? OR LOWER(p.descripcion) LIKE ? OR LOWER(p.marca) LIKE ? OR LOWER(p.modelo) LIKE ? OR LOWER(COALESCE(h.proveedor,'')) LIKE ?)"
        like = f"%{q2}%"
        hparams += [like, like, like, like, like]
    if iso_from:
        hist_sql += " AND h.created_at >= ?"
        hparams.append(iso_from)
    if iso_to:
        hist_sql += " AND h.created_at <= ?"
        hparams.append(iso_to)
    hist_sql += " ORDER BY h.created_at DESC LIMIT 200"
    hist = db.execute(hist_sql, hparams).fetchall()

    return render_template("repairs.html", send=send, inrep=inrep, hist=hist, q1=q1, q2=q2, scope=scope, date_from=date_from, date_to=date_to)


@app.route("/retired")
@login_required
def retired_page():
    q = (request.args.get("q") or "").strip().lower()
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()
    iso_from, iso_to = norm_date_range(date_from, date_to)

    db = get_db()
    ret_sql = """
      SELECT u.*, p.descripcion, p.tipo, p.marca, p.modelo,
        (SELECT h.created_at FROM history h WHERE h.unit_id=u.id AND h.type='RETIRE' ORDER BY h.created_at DESC LIMIT 1) AS retired_at
      FROM units u JOIN products p ON p.id=u.product_id
      WHERE u.status='RETIRED'
    """
    params = []
    if iso_from:
        ret_sql += " AND (SELECT h.created_at FROM history h WHERE h.unit_id=u.id AND h.type='RETIRE' ORDER BY h.created_at DESC LIMIT 1) >= ?"
        params.append(iso_from)
    if iso_to:
        ret_sql += " AND (SELECT h.created_at FROM history h WHERE h.unit_id=u.id AND h.type='RETIRE' ORDER BY h.created_at DESC LIMIT 1) <= ?"
        params.append(iso_to)
    ret_sql += " ORDER BY p.descripcion COLLATE NOCASE, COALESCE(u.serial,'')"
    units = db.execute(ret_sql, params).fetchall()

    if q:
        units = [u for u in units if q in f"{u['serial'] or ''} {u['descripcion']} {u['marca']} {u['modelo']} {u['tipo']} {u['last_sucursal'] or ''} {u['last_area'] or ''} {u['last_persona'] or ''}".lower()]

    return render_template("retired.html", units=units, q=q, date_from=date_from, date_to=date_to)

@app.route("/assignments")
@login_required
def assignments_page():
    q = (request.args.get("q") or "").strip().lower()
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()
    iso_from, iso_to = norm_date_range(date_from, date_to)
    db = get_db()
    rows_sql = """
      SELECT h.created_at, h.type, h.detalle,
             h.from_sucursal,h.from_area,h.from_persona,
             h.to_sucursal,h.to_area,h.to_persona,
             u.id as unit_id, u.serial, u.status, u.warranty_until,
             p.id as product_id, p.descripcion, p.tipo, p.marca, p.modelo, p.barcode,
             us.username
      FROM history h
      JOIN units u ON u.id=h.unit_id
      JOIN products p ON p.id=u.product_id
      JOIN users us ON us.id=h.user_id
      WHERE h.type IN ('ASSIGN','REASSIGN','RESTORE')
    """
    params = []
    if iso_from:
        rows_sql += " AND h.created_at >= ?"
        params.append(iso_from)
    if iso_to:
        rows_sql += " AND h.created_at <= ?"
        params.append(iso_to)
    rows_sql += " ORDER BY h.created_at DESC LIMIT 1000"
    rows = db.execute(rows_sql, params).fetchall()
    if q:
        rows = [r for r in rows if q in f"{r['descripcion']} {r['serial'] or ''} {r['to_sucursal'] or ''} {r['to_area'] or ''} {r['to_persona'] or ''} {r['from_sucursal'] or ''} {r['from_area'] or ''} {r['from_persona'] or ''} {r['username'] or ''}".lower()]
    return render_template("assignments.html", rows=rows, q=q, date_from=date_from, date_to=date_to)

@app.route("/queries")
@login_required
def queries_page():
    q = (request.args.get("q") or "").strip().lower()
    db = get_db()
    # Unidades: solo se muestran cuando se realiza una búsqueda (q)
    units = []
    if q:
        units = db.execute("""
          SELECT u.*, p.descripcion, p.tipo, p.marca, p.modelo, p.barcode,
                 pr.id AS provider_id, pr.nombre AS provider_nombre, pr.direccion AS provider_direccion, pr.contacto AS provider_contacto
          FROM units u JOIN products p ON p.id=u.product_id
          LEFT JOIN providers pr ON pr.id = p.proveedor_id
          ORDER BY u.status, p.descripcion COLLATE NOCASE, COALESCE(u.serial,'')
          LIMIT 2000
        """).fetchall()
        units = [u for u in units if q in f"{u['serial'] or ''} {u['status']} {u['warranty_until'] or ''} {u['descripcion']} {u['marca']} {u['modelo']} {u['tipo']} {u['barcode'] or ''} {u['sucursal'] or ''} {u['area'] or ''} {u['persona'] or ''}".lower()]

    hist = db.execute("""
      SELECT h.*, u.serial, p.descripcion, p.marca, p.modelo, us.username
      FROM history h
      JOIN units u ON u.id=h.unit_id
      JOIN products p ON p.id=u.product_id
      JOIN users us ON us.id=h.user_id
      ORDER BY h.created_at DESC
      LIMIT 30
    """).fetchall()
    if q:
        hist = db.execute("""
          SELECT h.*, u.serial, p.descripcion, p.marca, p.modelo, us.username
          FROM history h
          JOIN units u ON u.id=h.unit_id
          JOIN products p ON p.id=u.product_id
          JOIN users us ON us.id=h.user_id
          ORDER BY h.created_at DESC
          LIMIT 400
        """).fetchall()
        hist = [h for h in hist if q in f"{h['type']} {h['detalle']} {h['proveedor'] or ''} {h['serial'] or ''} {h['descripcion']} {h['marca']} {h['modelo']} {h['username']}".lower()]

    return render_template("queries.html", units=units, hist=hist, q=q, has_search=bool(q))

@app.route("/users", methods=["GET","POST"])
@admin_required
def users_page():
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "create":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            is_admin = 1 if request.form.get("is_admin") == "on" else 0
            if not username or not password:
                flash("Usuario y contraseña son obligatorios.", "error")
            else:
                try:
                    db.execute(
                        "INSERT INTO users(username,password_hash,is_admin,created_at) VALUES(?,?,?,?)",
                        (username, generate_password_hash(password), is_admin, utc_now_iso()),
                    )
                    db.commit()
                    flash("Usuario creado.", "ok")
                except sqlite3.IntegrityError:
                    flash("Ese usuario ya existe.", "error")

        elif action == "passwd":
            uid = int(request.form.get("user_id"))
            password = request.form.get("password") or ""
            if not password:
                flash("Contraseña vacía.", "error")
            else:
                db.execute("UPDATE users SET password_hash=? WHERE id=?",
                           (generate_password_hash(password), uid))
                db.commit()
                flash("Contraseña actualizada.", "ok")

        elif action == "delete":
            uid = int(request.form.get("user_id"))
            if uid == session.get("user_id"):
                flash("No podés borrarte a vos mismo.", "error")
            else:
                db.execute("DELETE FROM users WHERE id=?", (uid,))
                db.commit()
                flash("Usuario eliminado.", "ok")

    users = db.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY username COLLATE NOCASE").fetchall()
    return render_template("users.html", users=users)

# ---------------- Actions (POST) ----------------



@app.post("/api/product_add_units")
@login_required
def api_product_add_units():
    db = get_db()
    user = current_user()

    try:
        product_id = int((request.form.get("product_id") or "0").strip() or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "ID inválido."}), 400
    if product_id <= 0:
        return jsonify({"ok": False, "error": "ID inválido."}), 400

    p = db.execute("SELECT id FROM products WHERE id=?", (product_id,)).fetchone()
    if not p:
        return jsonify({"ok": False, "error": "Artículo no encontrado."}), 404

    warranty_until = (request.form.get("warranty_until") or "").strip() or None
    try:
        purchase_provider_id = int((request.form.get("proveedor_id") or "0").strip() or "0")
    except ValueError:
        purchase_provider_id = 0
    if purchase_provider_id <= 0:
        purchase_provider_id = None
    serials_raw = (request.form.get("serials") or "").strip()
    serials = []
    if serials_raw:
        for line in serials_raw.splitlines():
            s = line.strip()
            if s:
                serials.append(s)

    created = 0
    now = now_iso()

    if not serials:
        db.execute(
            """INSERT INTO units (product_id, serial, status, warranty_until, purchase_provider_id, sucursal, area, persona,
                                    last_sucursal, last_area, last_persona, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (product_id, None, "IN_STOCK", warranty_until, purchase_provider_id, None, None, None, None, None, None, now, now),
        )
        unit_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
        db.execute("INSERT INTO history (unit_id, user_id, type, detalle, created_at) VALUES (?,?,?,?,?)",
                   (unit_id, user["id"], "STOCK_ADD", "Ingreso a stock (barcode existente)", now))
        created = 1
    else:
        for s in serials:
            dup = db.execute(
                "SELECT id FROM units WHERE product_id=? AND serial=?",
                (product_id, s),
            ).fetchone()
            if dup:
                return jsonify({"ok": False, "error": f"Serial duplicado: {s}"}), 400

            db.execute(
                """INSERT INTO units (product_id, serial, status, warranty_until, purchase_provider_id, sucursal, area, persona,
                                        last_sucursal, last_area, last_persona, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (product_id, s, "IN_STOCK", warranty_until, purchase_provider_id, None, None, None, None, None, None, now, now),
            )
            unit_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
            db.execute("INSERT INTO history (unit_id, user_id, type, detalle, created_at) VALUES (?,?,?,?,?)",
                       (unit_id, user["id"], "STOCK_ADD", "Ingreso a stock (barcode existente)", now))
            created += 1

    db.commit()
    return jsonify({"ok": True, "created": created})

@app.post("/api/product_add")
@login_required
def api_product_add():
    db = get_db()
    barcode = (request.form.get("barcode") or "").strip()
    descripcion = (request.form.get("descripcion") or "").strip()
    tipo = (request.form.get("tipo") or "").strip()
    marca = (request.form.get("marca") or "").strip()
    modelo = (request.form.get("modelo") or "").strip()
    try:
        proveedor_id = int((request.form.get("proveedor_id") or "0").strip() or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "Proveedor inválido."}), 400
    if proveedor_id <= 0:
        proveedor_id = None
    purchase_provider_id = proveedor_id
    qty = int(request.form.get("qty") or "0")
    serials_raw = (request.form.get("serials") or "").strip()
    warranty_until = parse_date(request.form.get("warranty_until") or "")

    if not descripcion or not tipo or not marca or not modelo or qty <= 0:
        return jsonify({"ok": False, "error": "Faltan campos o cantidad inválida."}), 400

    p = None
    if barcode:
        p = db.execute("SELECT * FROM products WHERE barcode=? AND IFNULL(proveedor_id,0)=?", (barcode, int(proveedor_id or 0))).fetchone()
    if p is None and not barcode:
        p = db.execute("SELECT * FROM products WHERE (barcode IS NULL OR barcode='') AND lower(descripcion)=lower(?) AND lower(marca)=lower(?) AND lower(modelo)=lower(?)",
                       (descripcion, marca, modelo)).fetchone()

    if p is None:
        cur = db.execute("""
          INSERT INTO products(barcode,descripcion,tipo,marca,modelo,created_at,proveedor_id)
          VALUES(?,?,?,?,?,?,?)
        """,(barcode or None, descripcion, tipo, marca, modelo, utc_now_iso(), proveedor_id))
        product_id = cur.lastrowid
    else:
        product_id = p["id"]
        db.execute("UPDATE products SET barcode=?, descripcion=?, tipo=?, marca=?, modelo=?, proveedor_id=? WHERE id=?",
                   (barcode or p["barcode"], descripcion, tipo, marca, modelo, (p["proveedor_id"] if p else proveedor_id), product_id))

    created = 0
    ts = utc_now_iso()
    serials = []
    if serials_raw:
        for chunk in serials_raw.replace(",", "\n").splitlines():
            s = chunk.strip()
            if s:
                serials.append(s)
        seen=set()
        serials=[s for s in serials if not (s in seen or seen.add(s))]
        for sn in serials:
            try:
                db.execute("""
                  INSERT INTO units(product_id,serial,status,warranty_until,created_at,updated_at)
                  VALUES(?,?,?,?,?,?)
                """,(product_id, sn, "IN_STOCK", warranty_until, ts, ts))
                created += 1
            except sqlite3.IntegrityError:
                pass
    else:
        for _ in range(qty):
            db.execute("""
              INSERT INTO units(product_id,serial,status,warranty_until,created_at,updated_at)
              VALUES(?,?,?,?,?,?)
            """,(product_id, None, "IN_STOCK", warranty_until, ts, ts))
            created += 1

    db.commit()
    return jsonify({"ok": True, "created": created, "product_id": product_id})




@app.post("/api/product_update")
@login_required
def api_product_update():
    db = get_db()
    # allow all logged-in users, or restrict to admin? We'll restrict to admin for safety.
    user = current_user()
    if not user or not user["is_admin"] :
        return jsonify({"ok": False, "error": "Solo admin."}), 403

    try:
        product_id = int((request.form.get("product_id") or "0").strip() or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "ID inválido."}), 400
    barcode = (request.form.get("barcode") or "").strip() or None
    descripcion = (request.form.get("descripcion") or "").strip()
    tipo = (request.form.get("tipo") or "").strip()
    marca = (request.form.get("marca") or "").strip()
    modelo = (request.form.get("modelo") or "").strip()
    try:
        proveedor_id = int((request.form.get("proveedor_id") or "0").strip() or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "Proveedor inválido."}), 400
    if proveedor_id <= 0:
        proveedor_id = None

    if product_id <= 0 or not descripcion or not tipo or not marca or not modelo:
        return jsonify({"ok": False, "error": "Datos inválidos."}), 400
    try:
        db.execute("""
          UPDATE products
          SET barcode=?, descripcion=?, tipo=?, marca=?, modelo=?, proveedor_id=?
          WHERE id=?
        """, (barcode, descripcion, tipo, marca, modelo, proveedor_id, product_id))
        db.commit()
    except Exception as e:
        return jsonify({"ok": False, "error": "No se pudo guardar: " + str(e)}), 400
    return jsonify({"ok": True})

@app.post("/api/product_delete")
@login_required
def api_product_delete():
    db = get_db()
    product_id = int(request.form.get("product_id") or "0")
    if product_id <= 0:
        return jsonify({"ok": False, "error": "ID inválido."}), 400

    # Solo permitir borrar si no hay unidades fuera de stock (para evitar borrar historial crítico)
    counts = db.execute("""
      SELECT
        SUM(CASE WHEN status='IN_STOCK' THEN 1 ELSE 0 END) AS in_stock,
        SUM(CASE WHEN status='ASSIGNED' THEN 1 ELSE 0 END) AS assigned,
        SUM(CASE WHEN status='IN_REPAIR' THEN 1 ELSE 0 END) AS in_repair,
        SUM(CASE WHEN status='RETIRED' THEN 1 ELSE 0 END) AS retired,
        COUNT(*) AS total
      FROM units
      WHERE product_id=?
    """, (product_id,)).fetchone()

    if counts and ((counts["assigned"] or 0) > 0 or (counts["in_repair"] or 0) > 0 or (counts["retired"] or 0) > 0):
        return jsonify({"ok": False, "error": "No se puede eliminar: hay unidades asignadas / en reparación / dadas de baja."}), 400

    # Borrar primero historial de esas unidades, luego unidades, luego producto
    unit_ids = [r["id"] for r in db.execute("SELECT id FROM units WHERE product_id=?", (product_id,)).fetchall()]
    if unit_ids:
        placeholders = ",".join(["?"] * len(unit_ids))
        db.execute(f"DELETE FROM history WHERE unit_id IN ({placeholders})", unit_ids)
        db.execute("DELETE FROM units WHERE product_id=?", (product_id,))

    db.execute("DELETE FROM products WHERE id=?", (product_id,))
    db.commit()
    return jsonify({"ok": True})

@app.post("/api/assign")
@login_required
def api_assign():
    db = get_db()
    product_id = int(request.form.get("product_id") or "0")
    sucursal = (request.form.get("sucursal") or "").strip()
    area = (request.form.get("area") or "").strip() or None
    persona = (request.form.get("persona") or "").strip() or None
    pc_name = (request.form.get("pc_name") or "").strip() or None
    detalle = (request.form.get("detalle") or "").strip()

    # selección manual de unidades (seriales)
    selected_raw = (request.form.get("unit_ids") or "").strip()
    ts = utc_now_iso()

    if product_id <= 0 or not sucursal:
        return jsonify({"ok": False, "error": "Datos inválidos."}), 400

    if selected_raw:
        selected_ids = [int(x) for x in selected_raw.split(",") if x.strip().isdigit()]
        if not selected_ids:
            return jsonify({"ok": False, "error": "Selección inválida."}), 400

        placeholders = ",".join(["?"] * len(selected_ids))
        rows = db.execute(f"""
          SELECT id, serial FROM units
          WHERE id IN ({placeholders}) AND product_id=? AND status='IN_STOCK'
        """, (*selected_ids, product_id)).fetchall()

        if len(rows) != len(selected_ids):
            return jsonify({"ok": False, "error": "Alguna unidad seleccionada no está disponible en stock."}), 400

        for u in rows:
            db.execute("""
              UPDATE units
              SET status='ASSIGNED', sucursal=?, area=?, persona=?, pc_name=?,
                  last_sucursal=?, last_area=?, last_persona=?, last_pc_name=?,
                  updated_at=?
              WHERE id=?
            """, (sucursal, area, persona, pc_name, sucursal, area, persona, pc_name, ts, u["id"]))
            add_history(u["id"], "ASSIGN", detalle, from_status="IN_STOCK", to_status="ASSIGNED",
                        from_loc=None, to_loc={"sucursal": sucursal, "area": area, "persona": persona, "pc_name": pc_name})
        db.commit()
        return jsonify({"ok": True, "assigned": len(rows)})

    qty = int(request.form.get("qty") or "0")
    if qty <= 0:
        return jsonify({"ok": False, "error": "Datos inválidos."}), 400

    units = db.execute("""
      SELECT id, serial FROM units
      WHERE product_id=? AND status='IN_STOCK'
      ORDER BY CASE WHEN serial IS NOT NULL AND serial!='' THEN 0 ELSE 1 END, id
      LIMIT ?
    """, (product_id, qty)).fetchall()

    if len(units) < qty:
        return jsonify({"ok": False, "error": "Stock insuficiente."}), 400

    for u in units:
        db.execute("""
          UPDATE units
          SET status='ASSIGNED', sucursal=?, area=?, persona=?,
              last_sucursal=?, last_area=?, last_persona=?,
              updated_at=?
          WHERE id=?
        """, (sucursal, area, persona, pc_name, sucursal, area, persona, pc_name, ts, u["id"]))
        add_history(u["id"], "ASSIGN", detalle, from_status="IN_STOCK", to_status="ASSIGNED",
                    from_loc=None, to_loc={"sucursal": sucursal, "area": area, "persona": persona, "pc_name": pc_name})

    db.commit()
    return jsonify({"ok": True, "assigned": qty})


@app.post("/api/reassign")
@login_required
def api_reassign():
    unit_id = int(request.form.get("unit_id") or "0")
    sucursal = (request.form.get("sucursal") or "").strip()
    area = (request.form.get("area") or "").strip() or None
    persona = (request.form.get("persona") or "").strip() or None
    pc_name = (request.form.get("pc_name") or "").strip() or None
    detalle = (request.form.get("detalle") or "").strip()
    if unit_id<=0 or not sucursal or not detalle:
        return jsonify({"ok": False, "error": "Sucursal y detalle son obligatorios."}), 400

    db = get_db()
    u = unit_row(unit_id)
    if u["status"] != "ASSIGNED":
        return jsonify({"ok": False, "error": "La unidad no está ASIGNADA."}), 400
    from_loc={"sucursal":u["sucursal"],"area":u["area"],"persona":u["persona"],"pc_name":u["pc_name"] if "pc_name" in u.keys() else None}
    ts = utc_now_iso()
    db.execute("""
      UPDATE units SET sucursal=?, area=?, persona=?, pc_name=?, last_sucursal=?, last_area=?, last_persona=?, last_pc_name=?, updated_at=?
      WHERE id=?
    """,(sucursal, area, persona, pc_name, sucursal, area, persona, pc_name, ts, unit_id))
    add_history(unit_id, "REASSIGN", detalle, from_status="ASSIGNED", to_status="ASSIGNED",
                from_loc=from_loc, to_loc={"sucursal":sucursal,"area":area,"persona":persona,"pc_name":pc_name})
    db.commit()
    return jsonify({"ok": True})

@app.post("/api/repair_send")
@login_required
def api_repair_send():
    unit_id = int(request.form.get("unit_id") or "0")
    proveedor = (request.form.get("proveedor") or "").strip() or None
    detalle = (request.form.get("detalle") or "").strip()
    if unit_id<=0 or not detalle:
        return jsonify({"ok": False, "error": "Detalle obligatorio."}), 400
    db = get_db()
    u = unit_row(unit_id)
    if u["status"] in ("IN_REPAIR","RETIRED"):
        return jsonify({"ok": False, "error": "Estado inválido para enviar a reparación."}), 400
    from_loc={"sucursal":u["sucursal"],"area":u["area"],"persona":u["persona"],"pc_name":u["pc_name"] if "pc_name" in u.keys() else None}
    ts = utc_now_iso()
    db.execute("UPDATE units SET status='IN_REPAIR', updated_at=? WHERE id=?", (ts, unit_id))
    add_history(unit_id, "REPAIR_SEND", detalle, from_status=u["status"], to_status="IN_REPAIR",
                from_loc=from_loc, to_loc=from_loc, proveedor=proveedor)
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/repair_return")
@login_required
def api_repair_return():
    db = get_db()
    unit_id = int(request.form.get("unit_id") or "0")
    proveedor = (request.form.get("proveedor") or "").strip() or None
    detalle = (request.form.get("detalle") or "").strip()
    choice = (request.form.get("choice") or "ASSIGNED").strip().upper()

    if unit_id <= 0:
        return jsonify({"ok": False, "error": "ID inválido."}), 400

    u = db.execute("SELECT * FROM units WHERE id=?", (unit_id,)).fetchone()
    if not u:
        return jsonify({"ok": False, "error": "No existe."}), 404
    if u["status"] != "IN_REPAIR":
        return jsonify({"ok": False, "error": "El equipo no está en reparación."}), 400

    ts = utc_now_iso()
    from_loc = {"sucursal": u["sucursal"], "area": u["area"], "persona": u["persona"]}

    if choice == "IN_STOCK":
        db.execute("""
          UPDATE units
          SET status='IN_STOCK', sucursal=NULL, area=NULL, persona=NULL, updated_at=?
          WHERE id=?
        """, (ts, unit_id))
        add_history(unit_id, "REPAIR_RETURN", detalle, proveedor=proveedor,
                    from_status="IN_REPAIR", to_status="IN_STOCK",
                    from_loc=from_loc, to_loc=None)
        db.commit()
        return jsonify({"ok": True})

    # Default: volver a la última asignación (si existe). Si no, vuelve a stock.
    last_s = u["last_sucursal"]
    last_a = u["last_area"]
    last_p = u["last_persona"]

    if not last_s:
        db.execute("""
          UPDATE units
          SET status='IN_STOCK', sucursal=NULL, area=NULL, persona=NULL, updated_at=?
          WHERE id=?
        """, (ts, unit_id))
        add_history(unit_id, "REPAIR_RETURN", (detalle + " (sin última ubicación; vuelve a stock)").strip(),
                    proveedor=proveedor,
                    from_status="IN_REPAIR", to_status="IN_STOCK",
                    from_loc=from_loc, to_loc=None)
        db.commit()
        return jsonify({"ok": True})

    db.execute("""
      UPDATE units
      SET status='ASSIGNED', sucursal=?, area=?, persona=?,
          updated_at=?
      WHERE id=?
    """, (last_s, last_a, last_p, ts, unit_id))
    add_history(unit_id, "REPAIR_RETURN", detalle, proveedor=proveedor,
                from_status="IN_REPAIR", to_status="ASSIGNED",
                from_loc=from_loc, to_loc={"sucursal": last_s, "area": last_a, "persona": last_p})
    db.commit()
    return jsonify({"ok": True})


@app.post("/api/repair_return_stock")
@login_required
def api_repair_return_stock():
    unit_id = int(request.form.get("unit_id") or "0")
    proveedor = (request.form.get("proveedor") or "").strip() or None
    detalle = (request.form.get("detalle") or "").strip()
    if unit_id<=0 or not detalle:
        return jsonify({"ok": False, "error": "Detalle obligatorio."}), 400
    db = get_db()
    u = unit_row(unit_id)
    if u["status"] != "IN_REPAIR":
        return jsonify({"ok": False, "error": "La unidad no está en reparación."}), 400
    from_loc={"sucursal":u["sucursal"],"area":u["area"],"persona":u["persona"],"pc_name":u["pc_name"] if "pc_name" in u.keys() else None}
    ts = utc_now_iso()
    db.execute("""
      UPDATE units
      SET status='IN_STOCK', sucursal=NULL, area=NULL, persona=NULL, updated_at=?
      WHERE id=?
    """,(ts, unit_id))
    add_history(unit_id, "REPAIR_RETURN_STOCK", detalle, from_status="IN_REPAIR", to_status="IN_STOCK",
                from_loc=from_loc, to_loc=None, proveedor=proveedor)
    db.commit()
    return jsonify({"ok": True})

@app.post("/api/repair_return_assigned")
@login_required
def api_repair_return_assigned():
    unit_id = int(request.form.get("unit_id") or "0")
    proveedor = (request.form.get("proveedor") or "").strip() or None
    detalle = (request.form.get("detalle") or "").strip()
    if unit_id<=0 or not detalle:
        return jsonify({"ok": False, "error": "Detalle obligatorio."}), 400
    db = get_db()
    u = unit_row(unit_id)
    if u["status"] != "IN_REPAIR":
        return jsonify({"ok": False, "error": "La unidad no está en reparación."}), 400
    if not u["last_sucursal"]:
        return jsonify({"ok": False, "error": "No hay última asignación registrada."}), 400
    to_loc={"sucursal":u["last_sucursal"],"area":u["last_area"],"persona":u["last_persona"]}
    from_loc={"sucursal":u["sucursal"],"area":u["area"],"persona":u["persona"],"pc_name":u["pc_name"] if "pc_name" in u.keys() else None}
    ts = utc_now_iso()
    db.execute("""
      UPDATE units
      SET status='ASSIGNED', sucursal=?, area=?, persona=?, updated_at=?
      WHERE id=?
    """,(to_loc["sucursal"], to_loc["area"], to_loc["persona"], ts, unit_id))
    add_history(unit_id, "REPAIR_RETURN_ASSIGNED", detalle, from_status="IN_REPAIR", to_status="ASSIGNED",
                from_loc=from_loc, to_loc=to_loc, proveedor=proveedor)
    db.commit()
    return jsonify({"ok": True})

@app.post("/api/retire")
@login_required
def api_retire():
    unit_id = int(request.form.get("unit_id") or "0")
    detalle = (request.form.get("detalle") or "").strip()
    if unit_id<=0 or not detalle:
        return jsonify({"ok": False, "error": "Detalle obligatorio."}), 400
    db = get_db()
    u = unit_row(unit_id)
    if u["status"] == "RETIRED":
        return jsonify({"ok": False, "error": "Ya está en BAJA."}), 400
    from_loc={"sucursal":u["sucursal"],"area":u["area"],"persona":u["persona"],"pc_name":u["pc_name"] if "pc_name" in u.keys() else None}
    ts = utc_now_iso()
    db.execute("UPDATE units SET status='RETIRED', updated_at=? WHERE id=?", (ts, unit_id))
    add_history(unit_id, "DECOMMISSION", detalle, from_status=u["status"], to_status="RETIRED",
                from_loc=from_loc, to_loc=from_loc)
    db.commit()
    return jsonify({"ok": True})

@app.post("/api/restore")
@login_required
def api_restore():
    unit_id = int(request.form.get("unit_id") or "0")
    new_status = (request.form.get("new_status") or "").strip()
    detalle = (request.form.get("detalle") or "").strip()
    sucursal = (request.form.get("sucursal") or "").strip()
    area = (request.form.get("area") or "").strip() or None
    persona = (request.form.get("persona") or "").strip() or None

    if unit_id<=0 or not detalle or new_status not in ("IN_STOCK","ASSIGNED"):
        return jsonify({"ok": False, "error": "Campos inválidos."}), 400

    db = get_db()
    u = unit_row(unit_id)
    if u["status"] != "RETIRED":
        return jsonify({"ok": False, "error": "La unidad no está en BAJA."}), 400
    from_loc={"sucursal":u["sucursal"],"area":u["area"],"persona":u["persona"],"pc_name":u["pc_name"] if "pc_name" in u.keys() else None}
    ts = utc_now_iso()

    if new_status == "IN_STOCK":
        db.execute("""
          UPDATE units SET status='IN_STOCK', sucursal=NULL, area=NULL, persona=NULL, updated_at=?
          WHERE id=?
        """,(ts, unit_id))
        add_history(unit_id, "RESTORE_FROM_RETIRED", detalle, from_status="RETIRED", to_status="IN_STOCK",
                    from_loc=from_loc, to_loc=None)
    else:
        if not sucursal:
            return jsonify({"ok": False, "error": "Sucursal es obligatoria para asignar."}), 400
        db.execute("""
          UPDATE units
          SET status='ASSIGNED', sucursal=?, area=?, persona=?,
              last_sucursal=?, last_area=?, last_persona=?,
              updated_at=?
          WHERE id=?
        """,(sucursal, area, persona, pc_name, sucursal, area, persona, pc_name, ts, unit_id))
        add_history(unit_id, "RESTORE_FROM_RETIRED", detalle, from_status="RETIRED", to_status="ASSIGNED",
                    from_loc=from_loc, to_loc={"sucursal":sucursal,"area":area,"persona":persona,"pc_name":pc_name})
    db.commit()
    return jsonify({"ok": True})


@app.get("/api/in_stock_units/<int:product_id>")
@login_required
def api_in_stock_units(product_id: int):
    db = get_db()
    rows = db.execute("""
      SELECT id, serial, warranty_until
      FROM units
      WHERE product_id=? AND status='IN_STOCK' AND serial IS NOT NULL AND serial!=''
      ORDER BY serial COLLATE NOCASE
    """, (product_id,)).fetchall()
    return jsonify({
        "ok": True,
        "units": [{"id": r["id"], "serial": r["serial"], "warranty_until": r["warranty_until"]} for r in rows]
    })





@app.get("/api/product_units/<int:product_id>")
@login_required
def api_product_units(product_id: int):
    db = get_db()
    rows = db.execute(
        """SELECT u.id, u.serial, u.status, u.sucursal, u.area, u.persona, u.warranty_until,
                  u.purchase_provider_id,
                  p.nombre AS purchase_provider_nombre
           FROM units u
           LEFT JOIN providers p ON p.id = u.purchase_provider_id
           WHERE u.product_id=?
           ORDER BY u.id DESC""",
        (product_id,),
    ).fetchall()
    return jsonify({"ok": True, "rows": [dict(r) for r in rows]})

@app.post("/api/unit_delete")
@login_required
def api_unit_delete():
    db = get_db()
    user = current_user()
    if not user or not user["is_admin"]:
        return jsonify({"ok": False, "error": "Solo administradores"}), 403
    try:
        unit_id = int((request.form.get("unit_id") or "0").strip() or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "ID inválido."}), 400
    if unit_id <= 0:
        return jsonify({"ok": False, "error": "ID inválido."}), 400
    u = db.execute("SELECT id, serial, status FROM units WHERE id=?", (unit_id,)).fetchone()
    if not u:
        return jsonify({"ok": False, "error": "Unidad no encontrada."}), 404
    # log before delete
    db.execute(
        "INSERT INTO history (unit_id, user_id, type, detalle, created_at) VALUES (?,?,?,?,?)",
        (unit_id, user["id"], "UNIT_DELETE", f"Eliminada unidad (serial {u['serial'] or '-'})", now_iso()),
    )
    db.execute("DELETE FROM units WHERE id=?", (unit_id,))
    db.commit()
    return jsonify({"ok": True})

@app.post("/api/unit_update_serial")
@login_required
def api_unit_update_serial():
    db = get_db()
    user = current_user()
    if not user or not user["is_admin"]:
        return jsonify({"ok": False, "error": "Solo administradores"}), 403

    try:
        unit_id = int((request.form.get("unit_id") or "0").strip() or "0")
    except ValueError:
        return jsonify({"ok": False, "error": "ID inválido."}), 400

    new_serial = (request.form.get("serial") or "").strip() or None

    u = db.execute("SELECT id, serial, product_id FROM units WHERE id=?", (unit_id,)).fetchone()
    if not u:
        return jsonify({"ok": False, "error": "Unidad no encontrada."}), 404

    if new_serial:
        dup = db.execute(
            "SELECT id FROM units WHERE product_id=? AND serial=? AND id<>?",
            (u["product_id"], new_serial, unit_id),
        ).fetchone()
        if dup:
            return jsonify({"ok": False, "error": "Ya existe ese serial en este artículo."}), 400

    db.execute("UPDATE units SET serial=?, updated_at=? WHERE id=?", (new_serial, now_iso(), unit_id))
    db.execute(
        "INSERT INTO history (unit_id, user_id, type, detalle, created_at) VALUES (?,?,?,?,?)",
        (unit_id, user["id"], "SERIAL_UPDATE", f"Serial: {u['serial'] or '-'} -> {new_serial or '-'}", now_iso()),
    )
    db.commit()
    return jsonify({"ok": True})

@app.get("/api/unit_info/<int:unit_id>")
@login_required
def api_unit_info(unit_id: int):
    db = get_db()
    u = db.execute("""
      SELECT u.*, p.descripcion, p.tipo, p.marca, p.modelo, p.barcode,
             pr.id AS provider_id, pr.nombre AS provider_nombre, pr.direccion AS provider_direccion, pr.contacto AS provider_contacto
      FROM units u JOIN products p ON p.id=u.product_id
      LEFT JOIN providers pr ON pr.id = p.proveedor_id
      WHERE u.id=?
    """, (unit_id,)).fetchone()
    if u is None:
        return jsonify({"ok": False, "error": "Unidad no encontrada."}), 404

    hist = db.execute("""
      SELECT h.*, us.username
      FROM history h JOIN users us ON us.id=h.user_id
      WHERE h.unit_id=?
      ORDER BY h.created_at DESC
      LIMIT 200
    """, (unit_id,)).fetchall()

    unit = dict(u)
    provider = None
    if unit.get("provider_id"):
        provider = {
            "id": unit.get("provider_id"),
            "nombre": unit.get("provider_nombre"),
            "direccion": unit.get("provider_direccion"),
            "contacto": unit.get("provider_contacto"),
        }
    # limpiar claves internas
    for k in ["provider_id","provider_nombre","provider_direccion","provider_contacto"]:
        unit.pop(k, None)

    return jsonify({
        "ok": True,
        "unit": unit,
        "provider": provider,
        "history": [dict(h) for h in hist],
    })



@app.get("/api/provider_info/<int:provider_id>")
@login_required
def api_provider_info(provider_id: int):
    db = get_db()
    p = db.execute("SELECT * FROM providers WHERE id=?", (provider_id,)).fetchone()
    if not p:
        return jsonify({"ok": False, "error": "Proveedor no encontrado."}), 404
    return jsonify({"ok": True, "provider": dict(p)})

@app.get("/api/product_info/<int:product_id>")
@login_required
def api_product_info(product_id: int):
    serial_filter = (request.args.get('serial') or '').strip()
    db = get_db()
    p = db.execute("""
      SELECT p.*, pr.id AS provider_id, pr.nombre AS provider_nombre, pr.direccion AS provider_direccion, pr.contacto AS provider_contacto
      FROM products p
      LEFT JOIN providers pr ON pr.id = p.proveedor_id
      WHERE p.id=?
    """, (product_id,)).fetchone()
    if p is None:
        return jsonify({"ok": False, "error": "Producto no encontrado."}), 404

    product = dict(p)
    provider = None
    if product.get("provider_id"):
        provider = {
            "id": product.get("provider_id"),
            "nombre": product.get("provider_nombre"),
            "direccion": product.get("provider_direccion"),
            "contacto": product.get("provider_contacto"),
        }
    for k in ["provider_id", "provider_nombre", "provider_direccion", "provider_contacto"]:
        product.pop(k, None)

    counts = db.execute("""
      SELECT
        SUM(CASE WHEN status='IN_STOCK' THEN 1 ELSE 0 END) AS in_stock,
        SUM(CASE WHEN status='ASSIGNED' THEN 1 ELSE 0 END) AS assigned,
        SUM(CASE WHEN status='IN_REPAIR' THEN 1 ELSE 0 END) AS in_repair,
        SUM(CASE WHEN status='RETIRED' THEN 1 ELSE 0 END) AS retired,
        COUNT(*) AS total
      FROM units
      WHERE product_id=?
    """, (product_id,)).fetchone()

    units = db.execute("""
      SELECT id, serial, status, warranty_until, sucursal, area, persona, last_sucursal, last_area, last_persona, updated_at
      FROM units
      WHERE product_id=?
      ORDER BY
        CASE status WHEN 'IN_STOCK' THEN 0 WHEN 'ASSIGNED' THEN 1 WHEN 'IN_REPAIR' THEN 2 ELSE 3 END,
        COALESCE(serial,''), id
      LIMIT 250
    """, (product_id,)).fetchall()
    if serial_filter:
        units = [u for u in units if (u['serial'] or '').lower().find(serial_filter.lower())!=-1]

    hist = db.execute("""
      SELECT h.*, u.serial, us.username
      FROM history h
      JOIN units u ON u.id=h.unit_id
      JOIN users us ON us.id=h.user_id
      WHERE u.product_id=?
      ORDER BY h.created_at DESC
      LIMIT 250
    """, (product_id,)).fetchall()

    return jsonify({
        "ok": True,
        "product": product,
        "provider": provider,
        "counts": dict(counts) if counts else {},
        "units": [dict(u) for u in units],
        "history": [dict(h) for h in hist],
    })



@app.get("/manage_products")
@login_required
def manage_products_page():
    db = get_db()
    q = (request.args.get("q") or "").strip()
    barcode = (request.args.get("barcode") or "").strip()
    serial = (request.args.get("serial") or "").strip()
    tipo = (request.args.get("tipo") or "").strip()
    marca = (request.args.get("marca") or "").strip()
    modelo = (request.args.get("modelo") or "").strip()
    proveedor_id = (request.args.get("proveedor_id") or "").strip()

    params = []
    where = ["1=1"]
    if q:
        where.append("(p.descripcion LIKE ? OR p.tipo LIKE ? OR p.marca LIKE ? OR p.modelo LIKE ? OR p.barcode LIKE ?)")
        params += [f"%{q}%"] * 5
    if barcode:
        where.append("p.barcode LIKE ?")
        params.append(f"%{barcode}%")
    if serial:
        where.append("EXISTS (SELECT 1 FROM units u WHERE u.product_id=p.id AND u.serial LIKE ?)")
        params.append(f"%{serial}%")
    if tipo:
        where.append("p.tipo LIKE ?")
        params.append(f"%{tipo}%")
    if marca:
        where.append("p.marca LIKE ?")
        params.append(f"%{marca}%")
    if modelo:
        where.append("p.modelo LIKE ?")
        params.append(f"%{modelo}%")
    if proveedor_id and proveedor_id.isdigit() and int(proveedor_id) > 0:
        where.append("IFNULL(p.proveedor_id,0)=?")
        params.append(int(proveedor_id))

    products = db.execute(f"""
        SELECT p.*,
               COALESCE(pr.nombre,'') AS proveedor_nombre,
               (SELECT COUNT(*) FROM units u WHERE u.product_id=p.id) AS unidades,
               (SELECT SUM(CASE WHEN u.status='IN_STOCK' THEN 1 ELSE 0 END) FROM units u WHERE u.product_id=p.id) AS en_stock
        FROM products p
        LEFT JOIN providers pr ON pr.id=p.proveedor_id
        WHERE {' AND '.join(where)}
        ORDER BY p.id DESC
        LIMIT 200
    """, params).fetchall()

    providers = db.execute("SELECT id, nombre FROM providers ORDER BY nombre").fetchall()
    return render_template("manage_products.html", products=products, providers=providers,
                           q=q, barcode=barcode, serial=serial, tipo=tipo, marca=marca, modelo=modelo, proveedor_id=proveedor_id)


@app.post("/manage_products/product/<int:product_id>/update")
@login_required
def manage_product_update(product_id: int):
    db = get_db()
    user = current_user()
    if not user or not user["is_admin"]:
        return jsonify({"ok": False, "error": "Solo administradores"}), 403

    descripcion = (request.form.get("descripcion") or "").strip()
    tipo = (request.form.get("tipo") or "").strip()
    marca = (request.form.get("marca") or "").strip()
    modelo = (request.form.get("modelo") or "").strip()
    barcode = (request.form.get("barcode") or "").strip() or None
    proveedor_id = (request.form.get("proveedor_id") or "").strip()
    proveedor_id = int(proveedor_id) if proveedor_id.isdigit() else None

    if barcode:
        dup = db.execute(
            "SELECT id FROM products WHERE barcode=? AND IFNULL(proveedor_id,0)=? AND id<>?",
            (barcode, int(proveedor_id or 0), product_id),
        ).fetchone()
        if dup:
            return jsonify({"ok": False, "error": "Ya existe otro producto con ese barcode para ese proveedor."}), 400

    db.execute("""
        UPDATE products
        SET descripcion=?, tipo=?, marca=?, modelo=?, barcode=?, proveedor_id=?, updated_at=?
        WHERE id=?
    """, (descripcion, tipo, marca, modelo, barcode, proveedor_id, utc_now_iso(), product_id))
    db.commit()
    return jsonify({"ok": True})


@app.post("/manage_products/unit/<int:unit_id>/update_serial")
@login_required
def manage_unit_update_serial(unit_id: int):
    db = get_db()
    user = current_user()
    if not user or not user["is_admin"]:
        return jsonify({"ok": False, "error": "Solo administradores"}), 403

    new_serial = (request.form.get("serial") or "").strip() or None
    u = db.execute("SELECT id, serial, product_id FROM units WHERE id=?", (unit_id,)).fetchone()
    if not u:
        return jsonify({"ok": False, "error": "Unidad no encontrada"}), 404

    if new_serial:
        dup = db.execute(
            "SELECT id FROM units WHERE product_id=? AND serial=? AND id<>?",
            (u["product_id"], new_serial, unit_id),
        ).fetchone()
        if dup:
            return jsonify({"ok": False, "error": "Ya existe ese serial en este producto."}), 400

    db.execute("UPDATE units SET serial=?, updated_at=? WHERE id=?", (new_serial, utc_now_iso(), unit_id))
    db.execute(
        "INSERT INTO history (unit_id, user_id, type, detalle, created_at) VALUES (?,?,?,?,?)",
        (unit_id, user["id"], "SERIAL_UPDATE", f"Serial: {u['serial'] or '-'} -> {new_serial or '-'}", utc_now_iso()),
    )
    db.commit()
    return jsonify({"ok": True})


@app.post("/manage_products/unit/<int:unit_id>/delete")
@login_required
def manage_unit_delete(unit_id: int):
    db = get_db()
    user = current_user()
    if not user or not user["is_admin"]:
        return jsonify({"ok": False, "error": "Solo administradores"}), 403

    u = db.execute("SELECT id FROM units WHERE id=?", (unit_id,)).fetchone()
    if not u:
        return jsonify({"ok": False, "error": "Unidad no encontrada"}), 404

    db.execute("DELETE FROM history WHERE unit_id=?", (unit_id,))
    db.execute("DELETE FROM units WHERE id=?", (unit_id,))
    db.commit()
    return jsonify({"ok": True})



@app.get("/reports")
@login_required
def reports_page():
    db = get_db()
    # filters
    rtype = (request.args.get("type") or "assign").strip()
    fmt = (request.args.get("fmt") or "").strip()  # empty => preview
    date_from = (request.args.get("from") or "").strip()
    date_to = (request.args.get("to") or "").strip()
    iso_from, iso_to = norm_date_range(date_from, date_to)

    q = (request.args.get("q") or "").strip().lower()
    serial = (request.args.get("serial") or "").strip().lower()
    barcode = (request.args.get("barcode") or "").strip()
    tipo = (request.args.get("tipo") or "").strip()
    marca = (request.args.get("marca") or "").strip().lower()
    modelo = (request.args.get("modelo") or "").strip().lower()
    sucursal = (request.args.get("sucursal") or "").strip().lower()
    area = (request.args.get("area") or "").strip().lower()
    persona = (request.args.get("persona") or "").strip().lower()
    pc = (request.args.get("pc") or "").strip().lower()
    prov_compra = (request.args.get("prov_compra") or "").strip().lower()
    prov_repar = (request.args.get("prov_repar") or "").strip().lower()

    def build_report_sql():
        where = []
        params = []
        # base by type
        if rtype == "bajas":
            where.append("h.type='DECOMMISSION'")
        elif rtype == "reasign":
            where.append("h.type='REASSIGN'")
        elif rtype == "reparaciones":
            where.append("h.type='REPAIR_SEND'")
        elif rtype == "hist_rep":
            where.append("h.type IN ('REPAIR_SEND','REPAIR_RETURN','REPAIR_RETURN_ASSIGNED','REPAIR_RETURN_STOCK')")
        else:  # assign
            where.append("h.type='ASSIGN'")

        if iso_from:
            where.append("h.created_at >= ?")
            params.append(iso_from)
        if iso_to:
            where.append("h.created_at <= ?")
            params.append(iso_to)

        # generic filters
        if q:
            where.append("(LOWER(p.descripcion) LIKE ? OR LOWER(p.tipo) LIKE ? OR LOWER(p.marca) LIKE ? OR LOWER(p.modelo) LIKE ? OR LOWER(COALESCE(u.serial,'')) LIKE ? OR LOWER(COALESCE(p.barcode,'')) LIKE ?)")
            params += [f"%{q}%"]*6
        if serial:
            where.append("LOWER(COALESCE(u.serial,'')) LIKE ?")
            params.append(f"%{serial}%")
        if barcode:
            where.append("COALESCE(p.barcode,'') LIKE ?")
            params.append(f"%{barcode}%")
        if tipo:
            where.append("p.tipo = ?")
            params.append(tipo)
        if marca:
            where.append("LOWER(p.marca) LIKE ?")
            params.append(f"%{marca}%")
        if modelo:
            where.append("LOWER(p.modelo) LIKE ?")
            params.append(f"%{modelo}%")

        # location filters: match either to_ or from_ or current
        if sucursal:
            where.append("(LOWER(COALESCE(h.to_sucursal,h.from_sucursal,u.sucursal,'')) LIKE ?)")
            params.append(f"%{sucursal}%")
        if area:
            where.append("(LOWER(COALESCE(h.to_area,h.from_area,u.area,'')) LIKE ?)")
            params.append(f"%{area}%")
        if persona:
            where.append("(LOWER(COALESCE(h.to_persona,h.from_persona,u.persona,'')) LIKE ?)")
            params.append(f"%{persona}%")
        if pc:
            where.append("(LOWER(COALESCE(u.pc_name,'')) LIKE ?)")
            params.append(f"%{pc}%")

        if prov_compra:
            where.append("(LOWER(COALESCE(pp.nombre,'')) LIKE ?)")
            params.append(f"%{prov_compra}%")
        if prov_repar:
            where.append("(LOWER(COALESCE(h.proveedor,'')) LIKE ?)")
            params.append(f"%{prov_repar}%")

        sql = f"""
          SELECT
            h.created_at AS fecha,
            h.type AS accion,
            p.descripcion, p.tipo, p.marca, p.modelo, p.barcode,
            COALESCE(pp.nombre,'') AS proveedor_compra,
            COALESCE(h.proveedor,'') AS proveedor_reparacion,
            COALESCE(u.serial,'') AS serial,
            COALESCE(u.pc_name,'') AS pc_name,
            COALESCE(h.from_sucursal,'') AS from_sucursal,
            COALESCE(h.from_area,'') AS from_area,
            COALESCE(h.from_persona,'') AS from_persona,
            COALESCE(h.to_sucursal,'') AS to_sucursal,
            COALESCE(h.to_area,'') AS to_area,
            COALESCE(h.to_persona,'') AS to_persona,
            h.detalle
          FROM history h
          JOIN units u ON u.id=h.unit_id
          JOIN products p ON p.id=u.product_id
          LEFT JOIN providers pp ON pp.id=u.purchase_provider_id
          WHERE {" AND ".join(where)}
          ORDER BY h.created_at DESC
        """
        return sql, params

    sql, params = build_report_sql()
    rows = db.execute(sql, params).fetchall()

    # Download
    if fmt in ("csv","pdf"):
        return reports_download(rows, rtype, fmt)

    tipos = [r["tipo"] for r in db.execute("SELECT DISTINCT tipo FROM products ORDER BY tipo COLLATE NOCASE").fetchall()]
    return render_template("reports.html", active="reports",
        rows=rows[:200], total=len(rows),
        tipos=tipos,
        rtype=rtype, date_from=date_from, date_to=date_to,
        q=q, serial=serial, barcode=barcode, tipo=tipo, marca=marca, modelo=modelo,
        sucursal=sucursal, area=area, persona=persona, pc=pc,
        prov_compra=prov_compra, prov_repar=prov_repar
    )


def reports_download(rows, rtype, fmt):
    # columns definition
    cols = [
        ("fecha","Fecha"),
        ("accion","Acción"),
        ("descripcion","Descripción"),
        ("tipo","Tipo"),
        ("marca","Marca"),
        ("modelo","Modelo"),
        ("barcode","Barcode"),
        ("proveedor_compra","Proveedor compra"),
        ("proveedor_reparacion","Proveedor reparación"),
        ("serial","Serial"),
        ("pc_name","Nombre PC"),
        ("from_sucursal","Desde Sucursal"),
        ("from_area","Desde Área"),
        ("from_persona","Desde Persona"),
        ("to_sucursal","A Sucursal"),
        ("to_area","A Área"),
        ("to_persona","A Persona"),
        ("detalle","Detalle"),
    ]
    filename = f"reporte_{rtype}_{utc_now_iso().replace(':','-')}.{fmt}"

    if fmt == "csv":
        import csv
        from io import StringIO
        si = StringIO()
        w = csv.writer(si)
        w.writerow([c[1] for c in cols])
        for r in rows:
            w.writerow([r[c[0]] if c[0] in r.keys() else "" for c in cols])
        out = si.getvalue().encode("utf-8-sig")
        return Response(out, mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    # PDF
    try:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except Exception:
        return jsonify({"ok": False, "error": "No se pudo generar PDF (falta dependencia reportlab). Instalá: pip install reportlab"}), 500

    from io import BytesIO
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=18, rightMargin=18, topMargin=18, bottomMargin=18)
    styles = getSampleStyleSheet()
    title_map = {
        "assign":"Asignaciones",
        "bajas":"Bajas",
        "reasign":"Reasignaciones",
        "reparaciones":"Reparaciones (envíos)",
        "hist_rep":"Historial de reparaciones",
    }
    title = title_map.get(rtype, rtype)
    elems = [Paragraph(f"Reporte: {title}", styles["Title"]),
             Paragraph(f"Generado: {utc_now_iso()} (UTC)", styles["Normal"]),
             Spacer(1, 10)]
    data = [[c[1] for c in cols]]
    for r in rows[:2000]:  # cap for readability/perf
        data.append([str(r[c[0]] if c[0] in r.keys() else "") for c in cols])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0), colors.HexColor("#111827")),
        ("TEXTCOLOR",(0,0),(-1,0), colors.white),
        ("GRID",(0,0),(-1,-1), 0.25, colors.HexColor("#374151")),
        ("FONTSIZE",(0,0),(-1,-1), 7),
        ("VALIGN",(0,0),(-1,-1), "TOP"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.HexColor("#0b1220"), colors.HexColor("#0f172a")]),
    ]))
    elems.append(table)
    doc.build(elems)
    pdf = buf.getvalue()
    buf.close()
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})



@app.get("/inventory")
@login_required
def inventory_page():
    db = get_db()
    q = (request.args.get("q") or "").strip().lower()
    serial = (request.args.get("serial") or "").strip().lower()
    barcode = (request.args.get("barcode") or "").strip().lower()
    invnum = (request.args.get("inv") or "").strip().lower()
    status = (request.args.get("status") or "").strip()

    rows = []
    if q or serial or barcode or invnum or status:
        where = []
        params = []
        if q:
            where.append("(p.descripcion LIKE ? OR p.tipo LIKE ? OR p.marca LIKE ? OR p.modelo LIKE ?)")
            params += [f"%{q}%"] * 4
        if serial:
            where.append("LOWER(u.serial) LIKE ?")
            params.append(f"%{serial}%")
        if barcode:
            where.append("LOWER(p.barcode) LIKE ?")
            params.append(f"%{barcode}%")
        if invnum:
            where.append("LOWER(u.inventory_number) LIKE ?")
            params.append(f"%{invnum}%")
        if status:
            where.append("u.status=?")
            params.append(status)

        sql = f"""
            SELECT u.id AS unit_id, u.serial, u.inventory_number, u.status,
                   u.sucursal, u.area, u.persona, u.pc_name, u.inventory_number, u.inventory_number, u.inventory_number, u.inventory_number,
                   p.id AS product_id, p.descripcion, p.tipo, p.marca, p.modelo, p.barcode,
                   COALESCE(pr.nombre,'') AS proveedor_nombre
            FROM units u
            JOIN products p ON p.id=u.product_id
            LEFT JOIN providers pr ON pr.id=p.proveedor_id
            WHERE {" AND ".join(where)}
            ORDER BY u.id DESC
            LIMIT 500
        """
        rows = db.execute(sql, params).fetchall()

    return render_template("inventory.html", rows=rows, q=q, serial=serial, barcode=barcode, inv=invnum, status=status, active="inventory")


@app.post("/api/unit_inventory_update/<int:unit_id>")
@login_required
def api_unit_inventory_update(unit_id: int):
    db = get_db()
    user = current_user()
    if not user or not user["is_admin"]:
        return jsonify({"ok": False, "error": "Solo administradores"}), 403

    inv = (request.form.get("inventory_number") or "").strip() or None

    u = db.execute("SELECT id, inventory_number FROM units WHERE id=?", (unit_id,)).fetchone()
    if not u:
        return jsonify({"ok": False, "error": "Unidad no encontrada"}), 404

    db.execute("UPDATE units SET inventory_number=?, updated_at=? WHERE id=?", (inv, utc_now_iso(), unit_id))
    db.execute(
        "INSERT INTO history (unit_id, user_id, type, detalle, created_at) VALUES (?,?,?,?,?)",
        (unit_id, user["id"], "INV_UPDATE", f"Inventario: {u['inventory_number'] or '-'} -> {inv or '-'}", utc_now_iso()),
    )
    db.commit()
    return jsonify({"ok": True})



@app.post("/api/return_to_stock/<int:unit_id>")
@login_required
def api_return_to_stock(unit_id: int):
    db = get_db()
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "No autenticado"}), 401

    u = db.execute("SELECT * FROM units WHERE id=?", (unit_id,)).fetchone()
    if not u:
        return jsonify({"ok": False, "error": "Unidad no encontrada"}), 404

    if u["status"] != "ASSIGNED":
        return jsonify({"ok": False, "error": "Solo se puede volver a stock desde estado ASSIGNED"}), 400

    ts = utc_now_iso()

    db.execute(
        """
        UPDATE units
        SET status='IN_STOCK',
            last_sucursal=?, last_area=?, last_persona=?, last_pc_name=?,
            sucursal=NULL, area=NULL, persona=NULL, pc_name=NULL,
            updated_at=?
        WHERE id=?
        """,
        (u["sucursal"], u["area"], u["persona"], u["pc_name"], ts, unit_id),
    )

    # History (best-effort)
    try:
        from_loc = {"sucursal": u["sucursal"], "area": u["area"], "persona": u["persona"], "pc_name": u["pc_name"]}
        to_loc = {"status": "IN_STOCK"}
        add_history(unit_id, user["id"], "RETURN_TO_STOCK", "Volver a stock", from_loc=from_loc, to_loc=to_loc)
    except Exception:
        db.execute(
            "INSERT INTO history (unit_id, user_id, type, detalle, created_at) VALUES (?,?,?,?,?)",
            (unit_id, user["id"], "RETURN_TO_STOCK", "Volver a stock", ts),
        )

    db.commit()
    return jsonify({"ok": True})


@app.get("/export/<kind>.csv")
@login_required
def export_csv(kind:str):
    db = get_db()
    if kind == "productos":
        rows = db.execute("SELECT id,barcode,descripcion,tipo,marca,modelo,created_at FROM products ORDER BY id").fetchall()
        header = ["id","barcode","descripcion","tipo","marca","modelo","created_at"]
    elif kind == "unidades":
        rows = db.execute("""
          SELECT id,product_id,serial,status,warranty_until,sucursal,area,persona,last_sucursal,last_area,last_persona,created_at,updated_at
          FROM units ORDER BY id
        """).fetchall()
        header = ["id","product_id","serial","status","warranty_until","sucursal","area","persona","last_sucursal","last_area","last_persona","created_at","updated_at"]
    elif kind == "historial":
        rows = db.execute("""
          SELECT h.id,h.unit_id,h.user_id,h.type,h.from_status,h.to_status,
                 h.from_sucursal,h.from_area,h.from_persona,
                 h.to_sucursal,h.to_area,h.to_persona,
                 h.proveedor,h.detalle,h.created_at,
                 p.descripcion AS producto_descripcion,
                 u.serial AS unit_serial
          FROM history h
          JOIN units u ON u.id=h.unit_id
          JOIN products p ON p.id=u.product_id
          ORDER BY h.id
        """).fetchall()
        header = ["id","unit_id","user_id","type","from_status","to_status",
                  "from_sucursal","from_area","from_persona",
                  "to_sucursal","to_area","to_persona",
                  "proveedor","detalle","created_at",
                  "producto_descripcion","unit_serial"]
    else:
        return "Tipo inválido", 404

    def esc(v):
        s = "" if v is None else str(v)
        if any(c in s for c in [",",'"',"\n","\r"]):
            return '"' + s.replace('"','""') + '"'
        return s

    out = []
    out.append(",".join(header))
    for r in rows:
        out.append(",".join(esc(r[h]) for h in header))
    csv = "\n".join(out)
    return app.response_class(csv, mimetype="text/csv")



# ---------------- Chat IA (local, robust fallback) ----------------

@app.get("/ai_chat")
@login_required
def ai_chat_page():
    return render_template("ai_chat.html", active="ai_chat")

def _try_exec(db, sql, params=()):
    try:
        cur = db.execute(sql, params)
        rows = cur.fetchall()
        return rows, None
    except Exception as e:
        return None, str(e)

def _norm(s: str) -> str:
    return (s or "").strip().lower()

def _best_match_from_list(q_low: str, options):
    for opt in options:
        o = _norm(opt)
        if o and o in q_low:
            return opt
    return None

def _extract_sucursal(db, q_low: str):
    rows, _ = _try_exec(db, "SELECT DISTINCT sucursal FROM units WHERE sucursal IS NOT NULL AND TRIM(sucursal)<>''", ())
    opts = [r["sucursal"] for r in (rows or [])]
    opts = sorted(opts, key=lambda x: len(_norm(x)), reverse=True)
    m = _best_match_from_list(q_low, opts)
    if m:
        return m
    mm = re.search(r"\bsucursal\s+([a-z0-9_\-\. ]{2,40})", q_low)
    if mm:
        return mm.group(1).strip()
    return None

def _extract_provider_name(db, q_low: str):
    rows, _ = _try_exec(db, "SELECT nombre FROM providers", ())
    opts = [r["nombre"] for r in (rows or [])]
    opts = sorted(opts, key=lambda x: len(_norm(x)), reverse=True)
    m = _best_match_from_list(q_low, opts)
    if m:
        return m
    mm = re.search(r"\bcon\s+(.+)$", q_low)
    if mm:
        return mm.group(1).strip()[:80]
    return None

def _extract_kind(q_low: str):
    if "impresora" in q_low or "printer" in q_low:
        return "impresora"
    if "notebook" in q_low or "laptop" in q_low or "nb" in q_low:
        return "notebook"
    if "monitor" in q_low:
        return "monitor"
    if "pc" in q_low or "desktop" in q_low:
        return "pc"
    return None

def _intent_from_q(q: str):
    ql = _norm(q)
    if any(k in ql for k in ["reparacion", "reparación", "en reparación", "en reparacion", "reparar"]):
        return "repairs"
    if any(k in ql for k in ["asignad", "asignación", "asignacion", "tiene", "tienen"]):
        return "assigned"
    if any(k in ql for k in ["baja", "bajas", "retirad", "decomis", "dado de baja"]):
        return "retired"
    if "stock" in ql:
        return "stock"
    return "unknown"

def _parse_time_range_iso(q: str):
    ql = _norm(q)
    now = datetime.now()
    start = None
    end = None
    if "hoy" in ql:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
    elif "este mes" in ql:
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = now
    else:
        m = re.search(r"ultim[oa]s?\s+(\d+)\s+d[ií]as", ql)
        if m:
            days = int(m.group(1))
            start = now - timedelta(days=days)
            end = now
    if start and end:
        return start.isoformat(timespec="seconds"), end.isoformat(timespec="seconds")
    return None, None

@app.post("/api/ai/chat")
@login_required
def api_ai_chat():
    db = get_db()
    q = (request.form.get("q") or "").strip()
    if not q:
        return jsonify({"ok": False, "error": "Consulta vacía"}), 400

    q_low = _norm(q)
    intent = _intent_from_q(q)
    t_from, t_to = _parse_time_range_iso(q)
    sucursal = _extract_sucursal(db, q_low)
    prov_name = _extract_provider_name(db, q_low)
    kind = _extract_kind(q_low)

    # Special: "qué impresora tiene <sucursal>" => assigned + kind filter
    if "impresora" in q_low and intent in ("assigned", "unknown"):
        intent = "assigned"
        kind = kind or "impresora"

    # Repairs: units.status = IN_REPAIR; enrich via last REPAIR_SEND in history
    if intent == "repairs":
        sql = """
            SELECT
              u.id AS unit_id,
              u.serial,
              u.inventory_number,
              p.descripcion, p.tipo, p.marca, p.modelo,
              COALESCE((
                SELECT h.proveedor FROM history h
                WHERE h.unit_id=u.id AND h.type='REPAIR_SEND'
                ORDER BY h.created_at DESC LIMIT 1
              ), '') AS proveedor_reparacion,
              COALESCE((
                SELECT h.detalle FROM history h
                WHERE h.unit_id=u.id AND h.type='REPAIR_SEND'
                ORDER BY h.created_at DESC LIMIT 1
              ), '') AS motivo,
              COALESCE((
                SELECT h.created_at FROM history h
                WHERE h.unit_id=u.id AND h.type='REPAIR_SEND'
                ORDER BY h.created_at DESC LIMIT 1
              ), '') AS enviado_el
            FROM units u
            JOIN products p ON p.id = u.product_id
            WHERE u.status='IN_REPAIR'
            ORDER BY u.updated_at DESC
            LIMIT 500
        """
        rws, _ = _try_exec(db, sql, ())
        rows = rws or []
        if prov_name:
            pn = _norm(prov_name)
            rows = [r for r in rows if pn in _norm(r.get("proveedor_reparacion"))]
        if t_from and t_to:
            rows = [r for r in rows if r.get("enviado_el") and t_from <= str(r["enviado_el"]) <= t_to]
        answer = f"Encontré {len(rows)} equipos en reparación." if rows else "No encontré equipos en reparación actualmente."
        return jsonify({"ok": True, "answer": answer, "sql": sql.strip(), "rows": [dict(r) for r in rows[:500]]})

    # Assigned units with optional filters (sucursal/proveedor/tipo)
    if intent == "assigned":
        params = []
        where = ["u.status='ASSIGNED'"]
        if sucursal:
            where.append("LOWER(u.sucursal) LIKE ?")
            params.append(f"%{_norm(sucursal)}%")
        if prov_name:
            where.append("""(
              LOWER(COALESCE(pp.nombre,'')) LIKE ?
              OR LOWER(COALESCE(pv.nombre,'')) LIKE ?
            )""")
            params.append(f"%{_norm(prov_name)}%")
            params.append(f"%{_norm(prov_name)}%")
        if kind:
            where.append("(LOWER(p.tipo) LIKE ? OR LOWER(p.descripcion) LIKE ?)")
            params.append(f"%{_norm(kind)}%")
            params.append(f"%{_norm(kind)}%")

        if not (sucursal or prov_name or kind) and len(q_low) >= 4:
            where.append("(LOWER(p.descripcion) LIKE ? OR LOWER(p.tipo) LIKE ? OR LOWER(p.marca) LIKE ? OR LOWER(p.modelo) LIKE ? OR LOWER(u.serial) LIKE ?)")
            for _ in range(5):
                params.append(f"%{q_low}%")

        sql = f"""
            SELECT
              u.id AS unit_id,
              u.serial,
              u.inventory_number,
              u.sucursal, u.area, u.persona, u.pc_name,
              p.descripcion, p.tipo, p.marca, p.modelo
            FROM units u
            JOIN products p ON p.id = u.product_id
            LEFT JOIN providers pp ON pp.id = u.purchase_provider_id
            LEFT JOIN providers pv ON pv.id = p.proveedor_id
            WHERE {' AND '.join(where)}
            ORDER BY u.updated_at DESC
            LIMIT 500
        """
        rws, _ = _try_exec(db, sql, tuple(params))
        rows = rws or []
        if rows:
            if sucursal and kind:
                answer = f"Encontré {len(rows)} {kind}(s) asignadas en {sucursal}."
            elif sucursal:
                answer = f"Encontré {len(rows)} equipos asignados en {sucursal}."
            else:
                answer = f"Encontré {len(rows)} equipos asignados."
        else:
            if sucursal and kind:
                answer = f"No encontré {kind}(s) asignadas en {sucursal}."
            elif sucursal:
                answer = f"No encontré equipos asignados en {sucursal}."
            else:
                answer = "No encontré equipos asignados."
        return jsonify({"ok": True, "answer": answer, "sql": sql.strip(), "rows": [dict(r) for r in rows[:500]]})

    # Retired (bajas): units.status = RETIRED
    if intent == "retired":
        sql = """
            SELECT
              u.id AS unit_id,
              u.serial,
              u.inventory_number,
              p.descripcion, p.tipo, p.marca, p.modelo,
              COALESCE((
                SELECT h.detalle FROM history h
                WHERE h.unit_id=u.id AND h.type='DECOMMISSION'
                ORDER BY h.created_at DESC LIMIT 1
              ), '') AS motivo,
              u.updated_at
            FROM units u
            JOIN products p ON p.id = u.product_id
            WHERE u.status='RETIRED'
            ORDER BY u.updated_at DESC
            LIMIT 500
        """
        rws, _ = _try_exec(db, sql, ())
        rows = rws or []
        if t_from and t_to:
            rows = [r for r in rows if r.get("updated_at") and t_from <= str(r["updated_at"]) <= t_to]
        answer = f"Encontré {len(rows)} bajas (RETIRADOS)." if rows else "No encontré bajas."
        return jsonify({"ok": True, "answer": answer, "sql": sql.strip(), "rows": [dict(r) for r in rows[:500]]})

    # Stock: count units in stock per product
    if intent == "stock":
        sql = """
            SELECT
              p.id AS product_id,
              p.descripcion, p.tipo, p.marca, p.modelo, p.barcode,
              COUNT(u.id) AS stock
            FROM units u
            JOIN products p ON p.id = u.product_id
            WHERE u.status='IN_STOCK'
            GROUP BY p.id
            ORDER BY stock DESC, p.descripcion
            LIMIT 500
        """
        rws, _ = _try_exec(db, sql, ())
        rows = rws or []
        answer = "Este es el stock disponible." if rows else "No encontré stock disponible."
        return jsonify({"ok": True, "answer": answer, "sql": sql.strip(), "rows": [dict(r) for r in rows[:500]]})

    answer = """No entendí del todo la consulta. Ejemplos:
- ¿qué hay en reparación?
- ¿qué impresora tiene sucursal Centro?
- equipos asignados en DIN
- bajas este mes
- stock impresoras
"""
    return jsonify({"ok": True, "answer": answer, "rows": []})



if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)

