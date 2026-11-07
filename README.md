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

## 1. Arranque rápido

Requisitos: Docker + Docker Compose (probado con Docker 29.9 / Compose 5.6).

```bash
git clone <repo> tcc-seguridad && cd tcc-seguridad
docker compose up -d --build          # levanta base de datos, app v1, app v2 y gateway TLS
docker compose ps                     # estado de los servicios
bash attacks/run-all.sh               # ejecuta la suite de ataques y genera las evidencias
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
