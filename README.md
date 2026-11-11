# SQL Injection Vulnerable Lab
### ISW-622 Pruebas de Software — Universidad Técnica Nacional

> ⚠️ **ADVERTENCIA**: esta aplicación contiene vulnerabilidades **intencionales**.
> Úsela solo en su computadora. **No la exponga a Internet.**
> Las técnicas de este laboratorio solo se practican en sistemas propios o con permiso.

## Inicio rápido

```bash
git clone <URL_DEL_REPOSITORIO>
cd <carpeta_del_repositorio>
git checkout -b nombre1_nombre2_nombre3      # su rama; nunca trabaje en main
docker compose up --build                    # http://localhost:5000
```

## Credenciales de prueba

| Usuario  | Contraseña  | Rol   |
|----------|-------------|-------|
| admin    | Admin123    | admin |
| analyst  | Analyst123  | user  |
| student  | Student123  | user  |

## Qué hay que hacer

1. **Explorar** la aplicación y leer `app.py`.
2. **Atacar**: demostrar cada vulnerabilidad (enunciado, paso 5).
3. **Corregir**: se recomienda un commit por vulnerabilidad.
4. **Verificar** su avance cuantas veces quiera:

```bash
docker compose run --rm web python check_fixes.py
```

El verificador ejecuta los ataques contra **su** código y muestra qué vulnerabilidades siguen
pendientes. `check_fixes.py` no se modifica.

## Vulnerabilidades (10)

| ID   | Tipo                                   | Dónde                              |
|------|----------------------------------------|------------------------------------|
| V-01 | SQL Injection – Login                  | `app.py`, ruta `/login`            |
| V-02 | SQL Injection – Búsqueda (UNION)       | `app.py`, ruta `/search`           |
| V-03 | Contraseñas en texto plano             | `app.py`, `init_db()`              |
| V-04 | SECRET_KEY en el código                | `app.py`, configuración            |
| V-05 | `debug=True` activo                    | `app.py`, final del archivo        |
| V-06 | Consulta SQL visible en pantalla       | `templates/search.html`            |
| V-07 | Menú Admin visible para todos          | `templates/layout.html`            |
| V-08 | Sin protección CSRF                    | formularios                        |
| V-09 | SQL Injection numérica                 | `app.py`, ruta `/book/<id>`        |
| V-10 | SQL Injection en ORDER BY              | `app.py`, ruta `/search` (`sort`)  |

Además hay fallas **no documentadas** (reto extra): búsquelas.

## Notas técnicas

- **La base de datos se recrea cada vez que arranca la app** (datos de prueba nuevos). Así, un cambio en
  cómo se guardan las contraseñas se aplica al reiniciar.
- `SECRET_KEY` y `FLASK_DEBUG` llegan como variables de entorno desde `docker-compose.yml`.
- Para V-08 hay que descomentar `Flask-WTF` en `requirements.txt` y reconstruir (`docker compose up --build`).
- El código se copia dentro de la imagen: **cada cambio en `app.py` o en las plantillas requiere**
  `docker compose up --build`.

## Estructura

```
├── app.py               ← lógica (aquí están las vulnerabilidades)
├── check_fixes.py       ← verificador automático (no modificar)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── db/                  ← SQLite (se crea sola)
├── templates/           layout, login, dashboard, search, book, admin
└── static/style.css
```

## Detener

```bash
docker compose down
```
