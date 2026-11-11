Notas - Laboratorio SQL Injection (ISW-622)

Equipo: Stefany, Christopher, Jeremy, Josue

Tabla de hallazgos

--------------------------------------------------

ID: V-01
Payload: admin' -- como usuario, contraseña cualquiera. Tambien se probo ' OR '1'='1' --
Donde: Login
Que paso: No dejo entrar, siguio pidiendo credenciales correctas en los dos casos
Por que: La consulta del login esta escrita en varias lineas en el codigo. El -- solo comenta el resto de esa linea, pero la linea siguiente que valida la contraseña queda intacta y sigue exigiendo que coincida

--------------------------------------------------

ID: V-02
Payload: %' UNION SELECT 1,2,3,4 --  /  %' UNION SELECT id, username, password, role FROM users --  /  %' UNION SELECT 1, name, sql, 'x' FROM sqlite_master --  /  %' UNION SELECT id, owner, note, 'x' FROM internal_notes --
Donde: Busqueda
Que paso: Se confirmo el numero de columnas (4), se extrajeron usuarios con password y rol en texto plano, se listaron todas las tablas de la base (incluida internal_notes, que no se usa en ningun modulo visible), y al leer internal_notes se encontro la bandera FLAG{utn-isw622-sqli-union-sqlite_master}
Por que: La busqueda concatena el texto directo en una sola linea, asi que el -- si logra comentar el resto de la consulta. El UNION permite combinar resultados de cualquier tabla de la base con la consulta original de libros, no solo de books

--------------------------------------------------

ID: V-03
Payload: Login con admin/Admin123 real, entrar al panel Admin
Donde: Admin
Que paso: La columna de contrasenas muestra el texto plano, legible, sin encriptar
Por que: El codigo guarda la contrasena tal cual se escribio al crear el usuario, no usa generate_password_hash

--------------------------------------------------

ID: V-04
Payload: no aplica, se vio directo en el codigo (app.py linea 45)
Donde: app.py, configuracion de la app
Que paso: SECRET_KEY esta escrita directo como texto en el codigo (dev-secret-key-insegura-1234)
Por que: Si alguien ve el codigo o el repo, puede falsificar sesiones usando esa misma clave. Deberia leerse de una variable de entorno, nunca quedar fija en el archivo

--------------------------------------------------

ID: V-05
Payload: no aplica, se vio al levantar la app
Donde: app.py, app.run al final del archivo
Que paso: En la consola de docker compose up salio "Debug mode: on" y un PIN de debugger
Por que: Con debug=True activo, cualquiera que llegue a un error puede usar el debugger interactivo de Flask y ejecutar codigo en el servidor. Nunca debe quedar asi fuera de desarrollo local

--------------------------------------------------

ID: V-06
Payload: igual que V-02 (cualquier busqueda, por ejemplo termino vacio con UNION a internal_notes)
Donde: Busqueda
Que paso: Salio un mensaje de advertencia que dice "Consulta SQL ejecutada (esto no deberia mostrarse)" mostrando la consulta completa, incluyendo el UNION usado
Por que: La app pasa la consulta cruda a la pantalla de busqueda en vez de ocultarla, lo que le facilita a cualquiera armar los ataques de union

--------------------------------------------------

ID: V-07
Payload: entrar con analyst y con student, mirar el menu de arriba antes de hacer clic en Admin
Donde: Menu de navegacion (layout.html)
Que paso: El enlace Admin aparece visible con las dos cuentas de rol user. Al hacer clic, el backend si bloquea y muestra "No tiene permisos para acceder al panel de administracion"
Por que: En layout.html el enlace Admin se muestra para cualquier usuario con sesion iniciada, sin revisar el rol. El backend protege la ruta por dentro, pero la interfaz no deberia ni mostrar la opcion a quien no puede usarla

--------------------------------------------------

ID: V-08
Payload: curl.exe -i -X POST -d "username=admin&password=Admin123" http://localhost:5000/login
Donde: Formularios (login)
Que paso: El servidor respondio 302 y redirigio a /dashboard, creando una sesion valida, aunque el POST vino de curl y no del formulario real
Por que: No hay ningun token CSRF que valide que el envio vino del formulario de la propia pagina, asi que cualquier sitio externo podria mandar ese mismo POST a nombre del usuario

--------------------------------------------------

ID: V-09
Payload: /book/0 UNION SELECT 1, username, password, role FROM users   y luego   /book/1'
Donde: /book/id
Que paso: El primero mezclo datos de usuarios en los campos del libro (titulo = admin, autor = Admin123, categoria = admin). El segundo (con comilla) dio error "unrecognized token" y libro no encontrado
Por que: El id se concatena directo en la consulta sin comillas y sin parametro, asi que cualquier SQL valido se ejecuta. Esto demuestra que quitar comillas no es suficiente defensa aqui, porque la inyeccion no depende de comillas

--------------------------------------------------

ID: V-10
Payload: cambiar con F12 el value del select sort de title a nombre_inexistente, y buscar
Donde: Busqueda (orden)
Que paso: Error en la base de datos: no such column: nombre_inexistente. En la consulta expuesta se vio que quedo ORDER BY nombre_inexistente
Por que: El valor de sort se concatena directo en el ORDER BY sin validarlo contra una lista de columnas permitidas

--------------------------------------------------

Observaciones generales



--------------------------------------------------

Correcciones aplicadas (resumen para la defensa)

V-01: Se cambio la consulta del login a parametrizada (?), separando la busqueda del usuario de la verificacion de contraseña, que ahora se hace en Python. Se probo que el login normal sigue funcionando y que admin' -- ya no entra. Commit: "V-01: consulta parametrizada en el login"
V-02: Se cambio la consulta de busqueda a parametrizada (?) usando el patron %termino% como parametro. El ORDER BY se dejo igual por ahora (eso es V-10). Se probo que la busqueda normal (security, 4 resultados) sigue igual y que el payload UNION ya no trae nada raro. Commit: "V-02: consulta parametrizada en la busqueda"
V-03:
V-04:
V-05:
V-06:
V-07:
V-08:
V-09:
V-10:
