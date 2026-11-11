"""
=============================================================
  SQL INJECTION VULNERABLE LAB  –  ISW-622 Pruebas de Software
  Universidad Técnica Nacional
=============================================================

  ⚠️  ESTE ARCHIVO CONTIENE VULNERABILIDADES INTENCIONALES ⚠️
  Uso exclusivo para laboratorio académico local.
  No exponer a Internet ni usar fuera de entorno controlado.

  Vulnerabilidades presentes (para que los estudiantes las encuentren):
    V-01  SQL Injection en login (concatenación directa)
    V-02  SQL Injection en búsqueda (concatenación directa, UNION)
    V-03  Contraseñas en texto plano (sin hashing)
    V-04  SECRET_KEY hardcodeada en el código fuente
    V-05  Modo debug=True activo (expone debugger interactivo)
    V-06  Exposición de la consulta SQL cruda en la interfaz
    V-07  Enlace "Admin" visible para todos los roles en la navegación
    V-08  Sin protección CSRF en formularios
    V-09  SQL Injection numérica en el detalle de un libro (/book/<id>)
    V-10  SQL Injection en el ORDER BY de la búsqueda (campo "sort")

  Para comprobar su avance ejecute el verificador:
    docker compose run --rm web python check_fixes.py
=============================================================
"""

import os
import sqlite3
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect

BASE_DIR = Path(__file__).resolve().parent
# LAB_DB_PATH permite al verificador usar una base de datos temporal.
DB_PATH = Path(os.environ.get("LAB_DB_PATH", BASE_DIR / "db" / "lab.db"))

app = Flask(__name__)

# ---------------------------------------------------------------
# V-04: SECRET_KEY hardcodeada en el código fuente.
# En una aplicación real debe cargarse desde una variable de
# entorno y nunca commitearse al repositorio.
# ---------------------------------------------------------------
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-insegura-1234")

# V-08: proteccion CSRF activada para todos los formularios POST
csrf = CSRFProtect(app)


# ---------------------------------------------------------------
# Conexión a la base de datos
# ---------------------------------------------------------------
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------
# Inicialización de la base de datos con datos de prueba.
# En este laboratorio la base se RECREA cada vez que arranca la
# aplicación, así cualquier cambio en el código (por ejemplo, el
# hashing de contraseñas) se aplica a datos nuevos.
# ---------------------------------------------------------------
def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection()
    cur = conn.cursor()

    for table in ("users", "books", "audit_log", "internal_notes"):
        cur.execute(f"DROP TABLE IF EXISTS {table}")

    cur.execute("""
    CREATE TABLE users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT    NOT NULL UNIQUE,
        password TEXT    NOT NULL,
        role     TEXT    NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE books (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        title    TEXT NOT NULL,
        author   TEXT NOT NULL,
        category TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event      TEXT NOT NULL,
        username   TEXT,
        detail     TEXT,
        timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Notas internas: nadie debería poder leerlas desde la aplicación.
    cur.execute("""
    CREATE TABLE internal_notes (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        owner  TEXT NOT NULL,
        note   TEXT NOT NULL
    )
    """)

    # -------------------------------------------------------
    # V-03: Contraseñas almacenadas en TEXTO PLANO.
    # Nunca deben almacenarse así en una aplicación real.
    # Deben usarse bcrypt, Argon2 o PBKDF2.
    # -------------------------------------------------------
    users = [
        ("admin",   generate_password_hash("Admin123"),   "admin"),
        ("analyst", generate_password_hash("Analyst123"), "user"),
        ("student", generate_password_hash("Student123"), "user"),
    ]
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        users
    )

    books = [
        ("Secure Coding Fundamentals",   "J. Howard",    "security"),
        ("Flask Web Patterns",           "A. Miller",    "development"),
        ("Practical SQL",                "A. DeBarros",  "database"),
        ("Threat Modeling Essentials",   "M. Silva",     "security"),
        ("Performance Testing Handbook", "R. Jones",     "qa"),
        ("OWASP Testing Guide",          "OWASP Team",   "security"),
        ("Clean Code",                   "R. Martin",    "development"),
        ("The Web Application Hacker",   "Stuttard",     "security"),
    ]
    cur.executemany(
        "INSERT INTO books (title, author, category) VALUES (?, ?, ?)",
        books
    )

    cur.executemany(
        "INSERT INTO internal_notes (owner, note) VALUES (?, ?)",
        [
            ("admin", "Recordar rotar la clave del servidor de respaldos."),
            ("admin", "FLAG{utn-isw622-sqli-union-sqlite_master}"),
        ]
    )

    conn.commit()
    conn.close()


def log_event(event, username=None, detail=None):
    """Registra un evento en el log de auditoría."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (event, username, detail) VALUES (?, ?, ?)",
        (event, username, detail)
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------

@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # ---------------------------------------------------
        # V-01: SQL INJECTION EN LOGIN
        # La consulta se construye concatenando directamente
        # el input del usuario sin ningún tipo de validación.
        #
        # Payload de ejemplo que omite la contraseña:
        #   usuario:  admin' --
        #   password: (cualquier cosa)
        #
        # Payload que accede sin conocer ningún usuario:
        #   usuario:  ' OR '1'='1' --
        #   password: (cualquier cosa)
        # ---------------------------------------------------
        conn = get_connection()
        try:
            user = conn.execute(
                "SELECT id, username, role, password FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        except Exception as e:
            flash(f"Error en la base de datos: {e}", "error")
            conn.close()
            return render_template("login.html")
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]
            log_event("LOGIN_OK", user["username"])
            flash("Inicio de sesión exitoso.", "success")
            return redirect(url_for("dashboard"))

        # Nota: el detalle del log incluye la consulta completa,
        # y con ella la contraseña que escribió el usuario.
        log_event("LOGIN_FAIL", username, "credenciales invalidas")
        flash("Credenciales incorrectas.", "error")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role")
    )


@app.route("/search", methods=["GET", "POST"])
def search():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    books     = []
    raw_query = None
    searched  = False
    sort      = "title"

    if request.method == "POST":
        searched = True
        term = request.form.get("term", "")
        sort = request.form.get("sort", "title")

        # V-10: lista blanca de columnas permitidas para ORDER BY.
        # Los nombres de columna no se pueden parametrizar con "?",
        # asi que se valida contra un conjunto fijo de valores conocidos.
        COLUMNAS_ORDEN_PERMITIDAS = {"title", "author", "category"}
        if sort not in COLUMNAS_ORDEN_PERMITIDAS:
            sort = "title"

        # ---------------------------------------------------
        # V-02: SQL INJECTION EN BÚSQUEDA
        # El término de búsqueda se inserta directamente en
        # la consulta con LIKE.
        #
        # Payload para extraer todos los usuarios:
        #   %' UNION SELECT id, username, password, role FROM users --
        #
        # Payload para verificar número de columnas:
        #   %' UNION SELECT 1,2,3,4 --
        #
        # V-10: el criterio de orden ("sort") también se concatena,
        # esta vez en el ORDER BY. Aquí NO se puede usar un
        # parámetro "?": los nombres de columnas no se parametrizan.
        # ---------------------------------------------------
        raw_query = (
            "SELECT id, title, author, category FROM books "
            "WHERE title || ' ' || author || ' ' || category LIKE ? "
            f"ORDER BY {sort}"
        )
        like_pattern = f"%{term}%"

        conn = get_connection()
        try:
            books = conn.execute(raw_query, (like_pattern,)).fetchall()
        except Exception as e:
            flash(f"Error en la base de datos: {e}", "error")
        conn.close()

    # V-06: La consulta SQL cruda se pasa al template y se
    # muestra en pantalla — expone la estructura interna de la BD.
    return render_template(
        "search.html", books=books,
        searched=searched, sort=sort
    )


@app.route("/book/<int:book_id>")
def book_detail(book_id):
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    # ---------------------------------------------------
    # V-09: SQL INJECTION NUMÉRICA
    # El identificador llega por la URL como texto y se
    # concatena SIN comillas. Como no hay comillas que
    # "cerrar", filtrar comillas NO sirve de defensa aquí.
    #
    # Ejemplos:
    #   /book/1 OR 1=1
    #   /book/0 UNION SELECT 1, username, password, role FROM users
    # ---------------------------------------------------
    conn = get_connection()
    book = None
    try:
        book = conn.execute(
            "SELECT id, title, author, category FROM books WHERE id = ?",
            (book_id,)
        ).fetchone()
    except Exception as e:
        flash(f"Error en la base de datos: {e}", "error")
    conn.close()

    if book is None:
        flash("Libro no encontrado.", "error")
    return render_template("book.html", book=book)


@app.route("/admin")
def admin():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        flash("No tiene permisos para acceder al panel de administración.", "error")
        log_event("ACCESS_DENIED", session.get("username"), "Intento de acceso a /admin")
        return redirect(url_for("dashboard"))

    conn  = get_connection()
    users = conn.execute("SELECT id, username, password, role FROM users ORDER BY id").fetchall()
    logs  = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()

    # Nota: se incluye la columna password (texto plano) para que
    # los estudiantes vean claramente la V-03 desde el panel admin.
    return render_template("admin.html", users=users, logs=logs)


@app.route("/logout")
def logout():
    log_event("LOGOUT", session.get("username"))
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("login"))


# La base se inicializa al arrancar (con python app.py o con el
# verificador) para que siempre exista con datos de prueba.
# ---------------------------------------------------------------
# V-05: debug=True activo.
# En modo debug, Flask activa un debugger interactivo en el
# navegador cuando ocurre un error. Cualquier visitante puede
# ejecutar código Python arbitrario en el servidor.
# Nunca debe usarse debug=True en producción.
# ---------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
