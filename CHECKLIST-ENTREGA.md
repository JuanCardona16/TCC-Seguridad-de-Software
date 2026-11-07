# Checklist de entrega — TCC Seguridad Informática 2026-2

Uso: marcar cada casilla antes de subir. Las rutas son relativas a la raíz del repositorio.

## Entrega final (20 de noviembre de 2026)

### 1. Proyecto completo — «carpeta con configuraciones, scripts o evidencias técnicas»

- [ ] `docker-compose.yml` levanta el laboratorio completo con un comando.
- [ ] `README.md` explica arranque, puertos, usuarios demo y advertencias de uso.
- [ ] `app/` contiene la aplicación Rust con los dos modos (`MODE=vulnerable` / `MODE=hardened`).
- [ ] `lab/` contiene las configuraciones: gateway TLS (`nginx.conf`), bases de datos (`initdb/`) y firewall (`nft.yml`).
- [ ] `attacks/` contiene los nueve ataques automatizados y `run-all.sh`.
- [ ] `evidence/results.json` con `fail = 0` (se verifica con `jq '.summary' evidence/results.json`).
- [ ] `evidence/http/<modo>/*.log` con la salida real de cada prueba.
- [ ] `evidence/network/*.pcap` con las capturas HTTP y TLS.
- [ ] `site/` con el panel interactivo y `site/build_data.py`.

### 2. Documento final

- [ ] `docs/informe/TCC-seguridad-informatica.pdf` generado con `bash docs/informe/build-pdf.sh`.
- [ ] Portada institucional con universidad, facultad, programa, centro tutorial, título, integrantes y docente.
- [ ] Índice de contenido con números de página verificados contra el PDF.
- [ ] Tablas sin desbordes: `python3 docs/informe/verificar_tablas.py` debe reportar 0 hallazgos.
- [ ] Todas las tablas y diagramas presentes en el PDF.
- [ ] Formato institucional aplicado si el docente exige la plantilla oficial.

### 3. Contenidos obligatorios de la actividad

- [ ] Caso seleccionado: aplicación web de gestión documental (simulada).
- [ ] Mínimo dos enfoques: se cubren **los cuatro** (OWASP Top 10, criptografía, MAGERIT, ataques de red).
- [ ] Diagrama de arquitectura segura → `docs/diagramas/arquitectura.svg` (§6.1 del informe).
- [ ] Flujo de datos e identificación de amenazas → `docs/diagramas/dfd-stride.svg` (§6.2).
- [ ] Propuesta de controles y contramedidas → §6.4 y `docs/riesgos/magerit.yml`.
- [ ] Implementación y simulación: cifrado, autenticación, firewall, pentesting y seguridad web.
- [ ] Documentación del proceso, las pruebas y los resultados → informe + panel de evidencias.

## Sustentación (21 de noviembre de 2026)

- [ ] `docs/sustentacion/slides.html` abierto y probado en el equipo de presentación.
- [ ] `docs/sustentacion/guion.md` leído por los tres integrantes.
- [ ] Ensayo completo con cronómetro, dos veces (objetivo: 9 minutos).
- [ ] Video de respaldo de la demostración descargado localmente.
- [ ] Distribución de roles lista para exponer (informe, Anexo C).
- [ ] Checklist técnico de los 30 minutos previos ejecutado.

## Pendientes que no dependen del código

- [ ] **Escribir al tutor por el avance del 31 de octubre** y pedir: (a) aval para reconstruirlo,
  (b) la plantilla oficial del documento, (c) criterios de la rúbrica de sustentación.
- [ ] Confirmar en la plataforma las fechas reales de entrega y si la plantilla cambió.
- [ ] Reemplazar los nombres de los integrantes en el informe y en las diapositivas.

## Generar el paquete

```bash
bash scripts/empaquetar.sh     # -> dist/TCC-seguridad-informatica-2026-2.zip
```
