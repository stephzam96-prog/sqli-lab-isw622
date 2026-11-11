"""
Verificador automático del laboratorio SQLi (ISW-622).

Ejecuta ataques reales contra SU versión de app.py (sin levantar el
servidor) y le dice qué vulnerabilidades ya están corregidas.

Uso (desde la carpeta del proyecto):
    docker compose run --rm web python check_fixes.py
    # o, si tiene Python y Flask instalados localmente:
    python check_fixes.py

NO modifique este archivo.
"""

import ast
import os
import re
import sys
import sqlite3
import tempfile
from pathlib import Path

# El verificador usa una base temporal y su propia clave secreta.
_TMP = tempfile.mkdtemp(prefix="sqli_check_")
os.environ["LAB_DB_PATH"] = str(Path(_TMP) / "check.db")
os.environ["SECRET_KEY"] = "clave-del-verificador-9f3a"
os.environ["FLASK_DEBUG"] = "0"
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import app as lab
except Exception as exc:  # error de sintaxis o de importación en el código del estudiante
    print("\nNo se pudo importar app.py:", repr(exc))
    print("Corrija el error y vuelva a ejecutar el verificador.")
    sys.exit(2)

SOURCE = (Path(__file__).resolve().parent / "app.py").read_text(encoding="utf-8")
RESULTS = []  # (id, descripcion, ok, pista)


def fresh_client():
    lab.init_db()
    return lab.app.test_client()


def hidden_fields(html):
    """Devuelve los <input type=hidden> de la página (para tokens CSRF)."""
    out = {}
    for tag in re.findall(r"<input[^>]*>", html, flags=re.I):
        if re.search(r'type\s*=\s*["\']hidden["\']', tag, flags=re.I):
            name = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag)
            value = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag)
            if name:
                out[name.group(1)] = value.group(1) if value else ""
    meta = re.search(r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)', html, flags=re.I)
    if meta:
        out.setdefault("csrf_token", meta.group(1))
    return out


def post(client, url, data, page=None, with_tokens=True):
    """POST que reenvía los campos ocultos de la página (tokens) salvo que se pida lo contrario."""
    payload = dict(data)
    if with_tokens:
        html = client.get(page or url).get_data(as_text=True)
        for k, v in hidden_fields(html).items():
            payload.setdefault(k, v)
    return client.post(url, data=payload, follow_redirects=False)


def login(client, user, pwd, with_tokens=True):
    post(client, "/login", {"username": user, "password": pwd}, page="/login", with_tokens=with_tokens)


def logged_in(client):
    r = client.get("/dashboard")
    return r.status_code == 200


def record(vid, desc, ok, hint):
    RESULTS.append((vid, desc, bool(ok), hint))


def safe(fn):
    try:
        return fn()
    except Exception as exc:  # una excepción en el código del estudiante cuenta como fallo
        return ("EXC", repr(exc))


# ---------------------------------------------------------------
# Pruebas funcionales (la aplicación debe seguir funcionando)
# ---------------------------------------------------------------
def f_login():
    c = fresh_client()
    for u, p in (("admin", "Admin123"), ("analyst", "Analyst123"), ("student", "Student123")):
        c2 = lab.app.test_client()
        login(c2, u, p)
        if not logged_in(c2):
            return False
    c3 = lab.app.test_client()
    login(c3, "admin", "incorrecta")
    return not logged_in(c3)

def f_search():
    c = fresh_client()
    login(c, "student", "Student123")
    r = post(c, "/search", {"term": "security", "sort": "title"}, page="/search").get_data(as_text=True)
    ok1 = all(t in r for t in ("Secure Coding Fundamentals", "Threat Modeling Essentials",
                               "OWASP Testing Guide", "The Web Application Hacker"))
    r2 = post(c, "/search", {"term": "Flask", "sort": "title"}, page="/search").get_data(as_text=True)
    return ok1 and "Flask Web Patterns" in r2 and "Clean Code" not in r2

def f_admin():
    c = fresh_client()
    login(c, "admin", "Admin123")
    ok_admin = c.get("/admin").status_code == 200
    c2 = lab.app.test_client()
    login(c2, "student", "Student123")
    r = c2.get("/admin")
    return ok_admin and r.status_code in (302, 401, 403)

def f_book():
    c = fresh_client()
    login(c, "student", "Student123")
    r = c.get("/book/1")
    return r.status_code == 200 and "Secure Coding Fundamentals" in r.get_data(as_text=True)

def f_sort():
    c = fresh_client()
    login(c, "student", "Student123")
    def order(sort):
        html = post(c, "/search", {"term": "", "sort": sort}, page="/search").get_data(as_text=True)
        titles = ["Clean Code", "Flask Web Patterns", "OWASP Testing Guide", "Performance Testing Handbook",
                  "Practical SQL", "Secure Coding Fundamentals", "Threat Modeling Essentials", "The Web Application Hacker"]
        pos = {t: html.find(t) for t in titles}
        if any(v < 0 for v in pos.values()):
            return None
        return sorted(titles, key=lambda t: pos[t])
    by_title = order("title")
    by_author = order("author")
    return (by_title is not None and by_author is not None
            and by_title[0] == "Clean Code"
            and by_author[0] == "Practical SQL" and by_author.index("Flask Web Patterns") < by_author.index("Secure Coding Fundamentals"))


# ---------------------------------------------------------------
# Pruebas de seguridad
# ---------------------------------------------------------------
def t_v01():
    c = fresh_client()
    login(c, "admin' --", "x")
    if logged_in(c):
        return False
    c2 = lab.app.test_client()
    login(c2, "' OR '1'='1' --", "x")
    if logged_in(c2):
        return False
    c3 = lab.app.test_client()
    login(c3, "x", "' OR '1'='1")
    return not logged_in(c3)

def t_v02():
    c = fresh_client()
    login(c, "student", "Student123")
    body = post(c, "/search", {"term": "%' UNION SELECT id, username, password, role FROM users --", "sort": "title"},
                page="/search").get_data(as_text=True)
    leaked = any(x in body for x in ("Admin123", "Analyst123", "Student123", "pbkdf2:", "scrypt:"))
    body2 = post(c, "/search", {"term": "%' UNION SELECT 1, name, sql, 'x' FROM sqlite_master --", "sort": "title"},
                 page="/search").get_data(as_text=True)
    return (not leaked) and ("CREATE TABLE" not in body2) and ("internal_notes" not in body2)

def t_v03():
    lab.init_db()
    conn = sqlite3.connect(lab.DB_PATH)
    rows = conn.execute("SELECT username, password FROM users").fetchall()
    conn.close()
    plains = {"Admin123", "Analyst123", "Student123"}
    if not rows or any(p in plains for _, p in rows):
        return False
    if not all(len(p) >= 40 and ("$" in p or ":" in p) for _, p in rows):
        return False
    # el hash debe verificarse con la contraseña correcta (y la prueba funcional de login lo confirma)
    return f_login()

def _literals():
    tree = ast.parse(SOURCE)
    return tree, [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]

def t_v04():
    _, lits = _literals()
    return (lab.app.config.get("SECRET_KEY") == os.environ["SECRET_KEY"]
            and not any("dev-secret-key-insegura" in l for l in lits))

def t_v05():
    tree, _ = _literals()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            for kw in n.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return False
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Attribute) and t.attr == "debug" and isinstance(n.value, ast.Constant) and n.value.value is True:
                    return False
    return True

def t_v06():
    c = fresh_client()
    login(c, "student", "Student123")
    body = post(c, "/search", {"term": "security", "sort": "title"}, page="/search").get_data(as_text=True)
    return re.search(r"SELECT\b.*\bFROM\b", body, flags=re.S) is None and "ORDER BY" not in body

def t_v07():
    c = fresh_client()
    login(c, "student", "Student123")
    student_html = c.get("/dashboard").get_data(as_text=True)
    c2 = lab.app.test_client()
    login(c2, "admin", "Admin123")
    admin_html = c2.get("/dashboard").get_data(as_text=True)
    return ('href="/admin"' not in student_html) and ('href="/admin"' in admin_html)

def t_v08():
    # Un envío SIN token debe ser rechazado, y uno CON token debe funcionar.
    c = fresh_client()
    r = post(c, "/login", {"username": "admin", "password": "Admin123"}, page="/login", with_tokens=False)
    rejected = (not logged_in(c))
    c2 = lab.app.test_client()
    login(c2, "admin", "Admin123", with_tokens=True)
    accepted = logged_in(c2)
    return rejected and accepted

def t_v09():
    c = fresh_client()
    login(c, "student", "Student123")
    r1 = c.get("/book/0 UNION SELECT 1, username, password, role FROM users").get_data(as_text=True)
    r2 = c.get("/book/1 OR 1=1").get_data(as_text=True)
    leaked = any(x in r1 for x in ("Admin123", "Analyst123", "Student123", "pbkdf2:", "scrypt:"))
    # "1 OR 1=1" no debe comportarse como "1": no debe devolver otro libro distinto
    return (not leaked) and f_book() and ("Secure Coding Fundamentals" not in r2)

def t_v10():
    c = fresh_client()
    login(c, "student", "Student123")
    r_err = post(c, "/search", {"term": "security", "sort": "columna_inexistente"}, page="/search").get_data(as_text=True)
    no_error = "no such column" not in r_err.lower()
    # Debe ignorar o rechazar el valor malicioso; no puede ejecutarlo.
    malicious = "(CASE WHEN 1=1 THEN author ELSE title END)"
    html = post(c, "/search", {"term": "", "sort": malicious}, page="/search").get_data(as_text=True)
    first = html.find("Practical SQL")      # primero si ordena por autor
    clean = html.find("Clean Code")         # primero si ordena por título
    executed = first >= 0 and clean >= 0 and first < clean
    return no_error and (not executed) and f_sort()


CHECKS = [
    ("V-01", "SQLi en login", t_v01, "Use una consulta parametrizada con ? y pase los valores como tupla."),
    ("V-02", "SQLi en búsqueda (UNION)", t_v02, "Parametrice el LIKE: pase f'%{term}%' como valor, no dentro del SQL."),
    ("V-03", "Contraseñas con hash", t_v03, "generate_password_hash() al crear y check_password_hash() al validar. El hash no se compara en SQL."),
    ("V-04", "SECRET_KEY desde el entorno", t_v04, "Lea os.environ.get('SECRET_KEY') y elimine la clave del código."),
    ("V-05", "Sin debug=True", t_v05, "No escriba debug=True; use la variable de entorno FLASK_DEBUG."),
    ("V-06", "Consulta SQL oculta", t_v06, "Quite el bloque que muestra raw_query (y no la pase al template)."),
    ("V-07", "Menú Admin solo para admin", t_v07, "En layout.html: {% if session.get('role') == 'admin' %} alrededor del enlace."),
    ("V-08", "Protección CSRF", t_v08, "Flask-WTF: CSRFProtect(app) y csrf_token() en cada formulario POST."),
    ("V-09", "SQLi numérica en /book/<id>", t_v09, "Use <int:book_id> en la ruta Y consulta parametrizada."),
    ("V-10", "SQLi en ORDER BY", t_v10, "Los nombres de columna no se parametrizan: use una lista blanca (diccionario) de columnas permitidas."),
]
FUNCTIONAL = [
    ("F-1", "El login válido sigue funcionando", f_login),
    ("F-2", "La búsqueda normal sigue funcionando", f_search),
    ("F-3", "El panel Admin funciona para admin y se bloquea a user", f_admin),
    ("F-4", "El detalle de libro sigue funcionando", f_book),
    ("F-5", "El ordenamiento por título y autor funciona", f_sort),
]

def main():
    print("=" * 66)
    print("  VERIFICADOR DEL LABORATORIO SQLi  -  ISW-622")
    print("=" * 66)
    print("\nFuncionamiento (la aplicación no debe romperse):")
    func_ok = True
    for fid, desc, fn in FUNCTIONAL:
        res = safe(fn)
        ok = res is True
        func_ok &= ok
        print(f"  [{'OK ' if ok else 'ERR'}] {fid}  {desc}" + ("" if ok else f"   <- {res if isinstance(res, tuple) else ''}"))
    print("\nVulnerabilidades:")
    fixed = 0
    for vid, desc, fn, hint in CHECKS:
        res = safe(fn)
        ok = res is True
        fixed += ok
        print(f"  [{'CORREGIDA' if ok else 'PENDIENTE'}] {vid}  {desc}")
        if not ok:
            print(f"               pista: {hint}" + (f"  (error: {res[1]})" if isinstance(res, tuple) else ""))
    # Advertencia (no cuenta como fallo): consultas armadas con f-strings.
    tree, _ = _literals()
    fstr_sql = 0
    for n in ast.walk(tree):
        if isinstance(n, ast.JoinedStr):
            text = "".join(v.value for v in n.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
            if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", text) and any(isinstance(v, ast.FormattedValue) for v in n.values):
                fstr_sql += 1
    if fstr_sql:
        print(f"\n  Advertencia: quedan {fstr_sql} consulta(s) SQL armadas con f-strings.")
        print("  Solo es aceptable si el valor interpolado sale de una lista blanca.")
        print("  Eliminar comillas del input NO es una defensa válida contra SQLi.")
    print("\n" + "-" * 66)
    print(f"  Corregidas: {fixed} de {len(CHECKS)}")
    if not func_ok:
        print("  Atención: hay pruebas funcionales fallando; una 'corrección' que rompe la app no cuenta.")
    print("-" * 66)
    print("  Que todo salga en verde no basta: asegúrese de poder explicar cada corrección.")
    sys.exit(0 if (fixed == len(CHECKS) and func_ok) else 1)


if __name__ == "__main__":
    main()
