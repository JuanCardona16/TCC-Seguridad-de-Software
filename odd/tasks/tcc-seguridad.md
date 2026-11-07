# TCC Seguridad Informática — MiniGestor Documental (Rust + Docker)

Curso: Seguridad Informática 2026-2 · CIPA de 3 integrantes · Entrega final 20/11/2026 · Sustentación 21/11/2026
Repo: `/home/juancardona/Projects/tcc-seguridad` · Laboratorio 100 % local (`127.0.0.1`) · Todo en Docker

## Specs

S1 — Entrega final (PDF de la actividad, verbatim): «Proyecto completo (carpeta con configuraciones, scripts o
evidencias técnicas)» y «Documento final: De acuerdo a la plantilla».

S2 — Enfoques (PDF, verbatim): «Seleccionar mínimo dos enfoques de seguridad del curso: Análisis de riesgos
(MAGERIT o ISO 27005) / Criptografía aplicada (hash, cifrado simétrico o asimétrico) / Seguridad en aplicaciones
web (OWASP Top 10) / Detección o simulación de ataques de red (ARP Spoofing, SQL Injection, MITM, XSS, etc.)».
Se implementan los cuatro: OWASP, criptografía y MAGERIT obligatorios; ataques de red como bonus medido.

S3 — Diseño (PDF, verbatim): «Diagrama de arquitectura segura», «Flujo de datos e identificación de amenazas»,
«Propuesta de controles o contramedidas».

S4 — Implementación (PDF, verbatim): «Mecanismos de cifrado, autenticación, firewall, pruebas de pentesting o
seguridad web» con «Herramientas: Kali Linux, VirtualBox, Wireshark, BurpSuite, Metasploit, Postman, etc.».
En este laboratorio: Burp/ZAP/sqlmap/hydra/nmap/tcpdump/Wireshark/Postman sobre Docker; sin Kali ni VirtualBox
obligatorios, con justificación técnica en el informe.

S5 — Sustentación (PDF, verbatim): 10 minutos con «Problema y solución planteada», «Pruebas y demostraciones
realizadas», «Vulnerabilidades detectadas y mitigaciones aplicadas», «Distribución de roles del grupo».

S6 — Pedido del usuario (L2, verbatim): «Quiero que se ejecute en docker de forma local y que tenga todo lo que
pide el tranajo, y que ademas tengamos una web donde mostrar cada cosa que se hiso y demas, de forma interactiva
y obviamente el documento del TCC.»

S7 — Pedido del usuario (L2, verbatim): «Que sea un proyecto simulado. Si es posible escriblelo en rust para que
rinda muy bien.»

S8 — CIPA de 3 personas: la sustentación debe mostrar la distribución de roles de los tres integrantes.

S9 — Ubicación y alcance: repo en `/home/juancardona/Projects/tcc-seguridad`; laboratorio aislado, todo publicado
solo en `127.0.0.1`, con banner de advertencia. Prohibido apuntar a sistemas reales (ORFEO, campus, red de la
universidad) o usar datos personales reales.

S10 — Estado del avance del 31/10: no se entregó y no hay novedad del tutor (L2). Existe un riesgo administrativo
que no se resuelve con código.

## Tasks

| ID | Tarea | Specs | Ruta | Commit |
|----|-------|-------|------|--------|
| T1 | Scaffold del repo, `docker compose` con red aislada, Postgres, modo doble y README con advertencias | S6, S9 | inline | `dfc7ed3` |
| T2 | App Rust v1 deliberadamente vulnerable (MD5, SQLi, XSS, IDOR, cookie forjable, upload sin validar, sin rate limit, `/debug/config`) | S2, S7 | inline | `b37aa91` |
| T3 | App Rust v2 endurecida (Argon2id, AES-256-GCM, sesión firmada + tabla `sessions`, TOTP, RBAC real, validación de upload, rate limit + lockout, cabeceras/CSP, auditoría, nginx TLS) | S2, S4 | inline | `b37aa91` |
| T4 | Suite de ataques ejecutable como spec: cada ataque debe tener éxito en v1 (RED) y quedar bloqueado en v2 (GREEN), con `evidence/results.json` | S2, S4 | inline | `9f67da2` |
| T5 | Evidencia de red: `tcpdump` en el bridge → `.pcap` con credenciales en claro (HTTP) vs cifradas (TLS); ARP spoofing queda como receta documentada | S2, S4 | inline | `9f67da2` |
| T6 | MAGERIT v3 ligero: activos, amenazas, riesgo = probabilidad × impacto, mapa de calor y salvaguardas mapeadas a los controles del código | S2, S3 | inline | `2a2b783` |
| T7 | Diagramas: arquitectura segura y DFD con amenazas (STRIDE) en SVG dentro del repo | S3 | inline | `2a2b783` |
| T8 | Sitio interactivo de evidencias en `127.0.0.1:18090`: matriz antes/después con log real, mapa de calor, inventario y diagramas | S6 | inline | `2b40a48` |
| T9 | Firewall y monitoreo: `nftables` en contenedor + regla de detección de intentos de intrusión | S4 | inline | `f3390ca` |
| T10 | Documento final Markdown → PDF con la estructura de la actividad (la plantilla oficial depende del tutor) | S1, S5 | inline | `f3390ca` |
| T11 | Deck de sustentación de 10 min + guion por rol (el video de respaldo lo graba la CIPA) | S5, S8 | inline | `f3390ca` |
| T12 | Empaquetado del entregable: `scripts/empaquetar.sh` + `CHECKLIST-ENTREGA.md` | S1, S6 | inline | `f3390ca` |
| T14 | Panel: visor de diagramas con zoom (rueda, arrastre, teclado) para mostrar los diagramas al docente | S6 | inline | `dc3e486` |
| T15 | Panel: ejecución de ataques en vivo con guardas, verificada de forma independiente y endurecida según los hallazgos | S6 | inline | `dc3e486` |
| T16 | Panel: revelado por fases con animaciones (streaming por sondeo, ritmo didáctico declarado) | S6 | inline | `f1a321b` |
| T13 | Escribir al tutor por el avance del 31/10 y pedir plantilla + criterios de rúbrica | S10, S1 | humano | — |

## Log

L1 (pedido original, verbatim): «/home/juancardona/Documents/universidad/TRABAJO COLABORATIVO
CONTEXTUALIZADO 2026-2.pdf Analiza esa actividad y hazme una propuesta para hacerla por favor.»

L2 (decisiones del usuario, verbatim):
- Avance 31/10: «No se entregó y no sabemos nada»
- Integrantes: «3 personas»
- Tema: «Quiero que se ejecute en docker de forma local y que tenga todo lo que pide el tranajo, y que ademas
  tengamos una web donde mostrar cada cosa que se hiso y demas, de forma interactiva y obviamente el documento
  del TCC.»
- Laboratorio: «Que sea un proyecto simulado. Si es posible escriblelo en rust para que rinda muy bien.»
- Ubicación: `/home/juancardona/Projects/tcc-seguridad`

L3 (evidencia de entorno, 2026-11-06): i5-12450HX, 12 hilos, 7.5 GiB RAM (3.8 GiB libres), 151 GB libres, VT-x
activo, Docker 29.9.2 + Compose 5.6.1, sin toolchain Rust en el host, sin VirtualBox/libvirt, sin pandoc.
Decisión: se compila dentro de Docker (imagen `rust:1-slim-bookworm`); no se instala nada en el host.

## Evidencia de ejecución

V1 completa al 2026-11-06 (todo verificado sobre el laboratorio levantado):

- Laboratorio operativo: `tcc-db`, `tcc-vuln` (:18080), `tcc-hard` (:18091), `tcc-gateway`
  (:18443 TLS, :18083 redirección), `tcc-evidence` (:18090), `tcc-attacker` (perfil tools).
- Suite de ataques: **18/18 PASS** (9 ataques × 2 modos, sin fallos ni omisiones) →
  `evidence/results.json`.
- Panel de evidencias: `/healthz` 200, `/data/results.json` con `{total:18, pass:18, fail:0,
  skip:0}`, `/data/magerit.json` con 12 riesgos y 6 activos, diagramas servidos, intento de
  path traversal del panel devuelve 404 y el estado vacío devuelve 200.
- Código: 2.174 líneas de Rust/HTML/shell propias en `app/` y 1.334 en `attacks/`, `site/` y
  `docs/riesgos/`; 241 dependencias de Rust fijadas en `Cargo.lock`.

Estado final de la ejecución (2026-11-06): **T1–T12 completas y verificadas**; queda T13, que depende
del usuario (correo al tutor) y dos pendientes humanos: reemplazar los nombres de los integrantes y
grabar el video de respaldo de la demo.

Verificaciones finales:
- `bash attacks/run-all.sh` → 18 PASS / 0 FAIL / 0 SKIP (segunda corrida tras las correcciones).
- Panel de evidencias: `/healthz` 200, matriz 18/18, 12 riesgos, diagramas servidos, path traversal 404,
  estado vacío 200.
- Informe: PDF de 414 KB generado con pandoc + Chromium; texto extraíble y verificable con `pdftotext`.
- Entregable: `dist/TCC-seguridad-informatica-2026-2.zip` (130 archivos, 369 KB) generado por
  `scripts/empaquetar.sh`, que se niega a empaquetar si hay expectativas fallidas.
- Firewall: ruleset `lab/firewall/lab.nft` cargado y volcado en `evidence/firewall-ruleset.txt`.
- Seis commits en la rama `feat/tcc-seguridad`.

## Verificación independiente del ejecutor en vivo (2026-11-06)

Se delegó una revisión de seguridad read-only a `gentle-ai-verify` sobre `site/server.py`, el
`Dockerfile` del panel, el servicio `evidence` y los scripts ejecutables.

Veredicto: **sin ejecución arbitraria de comandos, sin bypass de la lista blanca y sin lectura
arbitraria de archivos**. Hallazgos de aislamiento y recursos, todos corregidos en `dc3e486`:

| Severidad | Hallazgo | Corrección |
|---|---|---|
| Alto | Salida y cuerpo HTTP sin límite; caché compartido entre corridas | Cuerpo ≤ 4 KB (413), salida leída de archivo y recortada a 8 KB, caché por ejecución |
| Alto | El timeout no mataba procesos hijos | `start_new_session=True` + `SIGKILL` al grupo |
| Medio | El control de `Host` es falsificable dentro de `lab_net` | Token por proceso sin CORS + `X-Panel-Token` (CSRF / DNS rebinding) |
| Medio | El proceso corría como root | Usuario `panel` (uid 10001) |
| Medio | Fugas de rutas internas y tracebacks | Errores al log del contenedor, mensaje genérico al cliente |

Verificación posterior a las correcciones: sin token 403 · token inválido 403 · Host externo 403 ·
cuerpo 8 KB 413 · id con traversal 400 · ataque de terminal 409 · 01/03/05 en vulnerable `exit 0` ·
01/06 en endurecido `exit 1` · `id -u` = 10001 · `touch /site/x` falla (rootfs de solo lectura) ·
`bash attacks/run-all.sh` 18 PASS.
