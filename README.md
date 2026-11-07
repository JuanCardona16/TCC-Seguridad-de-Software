# MiniGestor Documental — laboratorio de seguridad (TCC Seguridad Informática 2026-2)

Proyecto aplicado del Trabajo Colaborativo Contextualizado: una aplicación web de gestión
documental escrita en **Rust**, con **dos modos del mismo binario** — uno deliberadamente
vulnerable y otro endurecido — para demostrar, con evidencia reproducible, el ciclo completo
de **auditoría → explotación → mitigación → re-verificación**.

Todo corre en **Docker, de forma local**. No requiere máquinas virtuales ni herramientas
instaladas en el host.

> ## Advertencia
> El modo `vulnerable` es una aplicación **intencionalmente insegura**, construida como material
> académico. Todos los puertos se publican únicamente en `127.0.0.1`. **No la expongas en una red
> pública, no la despliegues en ningún servidor y no apuntes la suite de ataques a sistemas que no
> sean este laboratorio.** Los datos son simulados: no hay información real de personas.

---

## 1. Arranque con un solo comando

```bash
./arrancar.sh
```

Hace todo en orden: comprueba Docker y que los puertos estén libres, compila la imagen, levanta los
seis contenedores, espera a que cada servicio responda, ejecuta la suite de ataques, refresca el panel
y lo abre en el navegador. Si algo falla, dice qué pasó y con qué comando mirar los registros.

| Comando | Para qué |
|---|---|
| `./arrancar.sh` | arranque completo: unos 2 min la primera vez, 45 s con la imagen ya compilada |
| `./arrancar.sh --sin-pruebas` | arranque rápido (~20 s) sin volver a correr la suite |
| `./arrancar.sh --sin-navegador` | no abre el navegador |
| `./arrancar.sh --limpiar` | laboratorio de cero: borra contenedores y volúmenes antes de arrancar |
| `./parar.sh` | apaga y conserva los datos |
| `./parar.sh --todo` | apaga y borra los volúmenes |

Salida esperada:

```
▸ Comprobando el entorno
  ✓ Docker 29.9.2 disponible
  ✓ Docker Compose 5.6.1
  ✓ puertos 18080, 18083, 18090, 18091 y 18443 libres
▸ Compilando la aplicación
▸ Levantando los servicios
▸ Esperando a que los servicios estén sanos
  ✓ aplicación vulnerable responde
  ✓ aplicación endurecida (TLS) responde
  ✓ panel de evidencias responde
▸ Ejecutando la suite de ataques
  ✓ las 18 expectativas se cumplieron
▸ Refrescando el panel con las evidencias actuales
```

Lo único que hace falta tener instalado es Docker con el plugin `compose`: el repositorio no necesita
Rust, Python ni herramientas de seguridad en el host, porque todo corre en contenedores.

### Arranque manual (equivalente, paso por paso)

```bash
git clone <repo> tcc-seguridad && cd tcc-seguridad
docker compose up -d --build                    # base, app v1, app v2, gateway TLS y panel
docker compose --profile tools up -d            # herramientas de red (tcpdump) para el ataque 09
docker compose ps                               # estado de los servicios
bash attacks/run-all.sh                         # suite de ataques y evidencias
docker compose restart evidence                 # refresca el panel con los resultados nuevos
```

| Servicio | URL local | Qué es |
|---|---|---|
| `app-vuln` (v1) | <http://127.0.0.1:18080> | Aplicación con los defectos sembrados |
| `gateway` (v2) | <https://127.0.0.1:18443> | Aplicación endurecida detrás de TLS (certificado autofirmado) |
| `app-hard` (v2 directo) | <http://127.0.0.1:18091> | Misma versión endurecida sin TLS, para comparar capas |
| `gateway` HTTP | <http://127.0.0.1:18083> | Solo redirige a HTTPS (301) |
| `evidence` | <http://127.0.0.1:18090> | Panel de evidencias: matriz, mapa de calor, diagramas con zoom y **ataques en vivo** |
| `db` | *sin publicar* | PostgreSQL, alcanzable solo dentro de `lab_net` |

Usuarios demo (los crea la app en el primer arranque):

| Usuario | Contraseña | Rol | Notas |
|---|---|---|---|
| `admin` | `admin123` | administrador | ve todos los documentos y la auditoría |
| `alice` | `alice123` | usuario | dueña de un documento confidencial |
| `bob` | `bob123` | usuario | se usa para los ataques de acceso indebido |

Herramientas de red (perfil opcional, necesario para la evidencia de captura de tráfico):

```bash
docker compose --profile tools up -d
```

---

## 2. Qué se busca demostrar

| Enfoque del curso | Dónde está en este proyecto |
|---|---|
| **Análisis de riesgos (MAGERIT v3)** | `docs/riesgos/` — activos, amenazas, riesgo = probabilidad × impacto, mapa de calor y salvaguardas |
| **Criptografía aplicada** | MD5 → Argon2id (contraseñas), AES-256-GCM (documentos en reposo), HMAC-SHA256 (sesiones), TOTP/RFC 6238 (2FA), TLS 1.2/1.3 (transporte) |
| **Seguridad web (OWASP Top 10)** | Los nueve ataques de `attacks/` mapeados a A01–A07 |
| **Ataques de red (bonus)** | `attacks/09-tls-plaintext.sh` — captura `tcpdump` en el bridge: HTTP en claro vs TLS cifrado |

---

## 3. Suite de ataques = especificación ejecutable

La suite es el contrato de verificación del trabajo:

* en el modo **vulnerable** cada ataque **debe tener éxito** (el defecto está presente);
* en el modo **endurecido** el mismo ataque **debe quedar bloqueado** (la mitigación funciona).

`attacks/run-all.sh` ejecuta los nueve ataques contra ambos modos, guarda la respuesta HTTP de
cada intento y escribe `evidence/results.json`. Devuelve código de salida ≠ 0 si alguna
expectativa no se cumple.

| # | Ataque | OWASP | Defecto en v1 | Control en v2 |
|---|---|---|---|---|
| 01 | SQL injection en la búsqueda | A03 | concatenación de SQL | consulta parametrizada |
| 02 | XSS almacenado en el título | A03 | salida HTML cruda | escape de salida |
| 03 | IDOR en `/docs/{id}` | A01 | sin verificación de dueño | verificación de propiedad + auditoría |
| 04 | Fuerza bruta en `/login` | A07 | sin límite ni bloqueo | ventana de 5/min + bloqueo 5 min + `limit_req` |
| 05 | Falsificación de cookie | A01 | `sid=usuario:rol` en texto plano | sesión en servidor firmada con HMAC |
| 06 | Hashes débiles | A02 | MD5 sin sal | Argon2id (19 MiB, t=2, p=1) |
| 07 | Path traversal en la carga | A04 | nombre del cliente como ruta | nombre opaco + cifrado |
| 08 | Cabeceras ausentes | A05 | ninguna | CSP, XFO, nosniff, Referrer-Policy, HSTS |
| 09 | Credenciales en claro | A02 | HTTP sin TLS | TLS + HSTS + cookies `Secure` |

Ejecución individual de un ataque:

```bash
bash attacks/01-sqli-search.sh http://127.0.0.1:18080 vulnerable
bash attacks/01-sqli-search.sh https://127.0.0.1:18443 hardened
```

---

### 3.1 Panel de evidencias y demostración en vivo

El panel (<http://127.0.0.1:18090>) no solo muestra las evidencias: permite **ejecutar los ataques
delante del docente**. Cada celda de la matriz tiene un botón ▶ que corre el mismo script que produce
las evidencias oficiales y muestra la salida real, el código de salida y el veredicto.

| Ataque | Desde el panel | Por qué |
|---|---|---|
| 01, 02, 03, 04, 05, 06, 08 | Sí (botón ▶) | Solo necesitan HTTP o la base de datos |
| 07 path traversal | No (⌘) | Necesita inspeccionar el filesystem del contenedor `app-vuln` |
| 09 captura de tráfico | No (⌘) | Necesita `tcpdump` con `NET_ADMIN` sobre la red del laboratorio |

Para los dos últimos el panel muestra el comando exacto a pegar en la terminal. Los diagramas se
amplían con clic: zoom con la rueda del mouse, arrastre para moverse y `Esc` para cerrar.

El panel abre con la **presentación del proyecto**: el problema, qué se hizo, cómo se hizo, cómo se
resolvió, los números del trabajo y los integrantes de la CIPA. Después vienen las secciones
demostrativas: demo en vivo, matriz antes/después, análisis de riesgos, diagramas y reproducción.

Al lanzar una prueba el panel no espera la respuesta completa: la ejecución arranca en el servidor y
el navegador sigue su avance (`POST /api/run/...` devuelve un `run_id`; `GET /api/run-progress/<id>`
entrega las fases y las líneas nuevas). Se ven las fases —validando, ejecutando, recolectando,
interpretando— con spinner, marca de tiempo real, efecto de tipeo en la salida, barra de progreso y
sello del veredicto al cierre.

El ataque real tarda milisegundos: **el ritmo del revelado es didáctico** y se ajusta con los botones
`Calmo / Normal / Rápido` (se recuerda en el navegador). La duración real medida se muestra al final,
y hay un botón «ver todo ya» para saltar las animaciones.

Guardas del ejecutor (es un laboratorio local, pero el endpoint ejecuta procesos):

1. **Token de sesión por proceso**: el panel pide `/api/token` (sin CORS, no cacheable) y lo envía
   en `X-Panel-Token`. Una página de otro origen no puede leer esa respuesta, así que no puede
   ejecutar nada (defensa contra CSRF y DNS rebinding).
2. Solo atiende peticiones cuyo encabezado `Host` sea `127.0.0.1` o `localhost`.
3. Lista blanca de siete ataques + patrón estricto del identificador; nunca se compone un comando
   con texto del cliente y se lanza sin shell (`Popen([...])`, sin `shell=True`).
4. El modo solo puede ser `vulnerable` o `hardened`, contra destinos fijos del laboratorio.
5. Una ejecución a la vez; cuerpo de la petición acotado a 4 KB; timeout de 120 s que **mata el grupo
   de procesos completo**; salida leída desde archivo y recortada a 8 KB.
6. Directorio temporal y caché de cookies propios de cada ejecución, borrados al terminar: las
   evidencias oficiales nunca se sobrescriben.
7. Contenedor sin privilegios: usuario `panel` (uid 10001, no root), sistema de archivos de **solo
   lectura**, `cap_drop: [ALL]`, `no-new-privileges`, sin *socket* de Docker y con el repositorio
   montado en `:ro`.

### 3.2 Diagramas generados y verificados

Los diagramas no están dibujados a mano: `docs/diagramas/generar_diagramas.py` los construye con
layout calculado (bandas, corredores para las flechas y etiquetas ancladas en los canales libres).
`docs/diagramas/verificar.py` revisa la geometría resultante —texto fuera del lienzo, texto sobre
texto, texto sobre una caja ajena y flechas que atraviesan cajas— y devuelve código de error si
encuentra algo.

```bash
python3 docs/diagramas/generar_diagramas.py   # regenera los dos SVG
python3 docs/diagramas/verificar.py           # 0 hallazgos = geometría limpia
```

### 3.3 Informe final en PDF

El informe se genera desde `docs/informe/TCC-seguridad-informatica.md` con portada institucional,
índice de contenido numerado y tablas con ancho de columna declarado:

```bash
bash docs/informe/build-pdf.sh
```

El script hace cinco pasos: pandoc convierte el Markdown, un ensamblador arma portada + índice +
cuerpo y aplica los anchos de tabla, se imprime un PDF de prueba para ubicar cada sección, el índice se
recompone con los números de página reales (iterando hasta estabilizar) y se imprime el PDF definitivo.
Al final, `verificar_tablas.py` mide cada celda en Chromium y falla si alguna palabra no cabe en su
columna o si una tabla desborda su ancho.

## 4. Estructura del repositorio

```
tcc-seguridad/
├── app/                     # aplicación Rust (axum + sqlx + askama-free views)
│   ├── src/
│   │   ├── auth.rs          # hashes, sesiones HMAC, TOTP RFC 6238
│   │   ├── crypto.rs        # AES-256-GCM en reposo
│   │   ├── db.rs            # esquema, semilla, auditoría
│   │   ├── routes/          # auth, documentos, administración
│   │   ├── security.rs      # cabeceras y limitador de intentos
│   │   ├── session.rs       # resolución de sesión por modo
│   │   └── views.rs         # HTML con escape de salida explícito
│   └── migrations/          # esquema PostgreSQL
├── attacks/                 # suite de ataques (spec ejecutable)
├── evidence/                # respuestas HTTP, capturas pcap, results.json
├── lab/
│   ├── gateway/             # TLS, HSTS y rate limit en nginx
│   ├── initdb/              # bases separadas por modo
│   └── firewall/            # nftables del laboratorio
├── docs/                    # informe, riesgos MAGERIT, diagramas
└── odd/tasks/               # trazabilidad de la ejecución del trabajo
```

---

## 5. Reproducibilidad y limpieza

```bash
docker compose down            # detiene, conserva volúmenes
docker compose down -v         # reinicia el laboratorio desde cero (borra datos)
docker compose logs -f app-vuln
```

---

## 6. Ética y alcance

* Laboratorio aislado y local; ninguna prueba se dirige a sistemas reales.
* Prohibido usar el material contra los sistemas de la universidad (ORFEO, campus virtual, red
  institucional) o contra cualquier servicio de terceros.
* Los datos son ficticios y las capturas de tráfico se generan dentro de la red del laboratorio.
* La clave maestra y el secreto de sesión incluidos son **valores de laboratorio**: su exposición
  es parte del ejercicio de auditoría, no una recomendación de diseño.
