# Guion de sustentación — 10 minutos

**Formato exigido por la actividad:** 10 minutos por CIPA, con cuatro contenidos obligatorios:
problema y solución, pruebas y demostraciones, vulnerabilidades detectadas y mitigaciones
aplicadas, y distribución de roles.

**Regla de oro:** la sustentación **se hace sobre el sistema funcionando**, no sobre diapositivas.
Las diapositivas (`slides.html`) son el guion visual; el panel de evidencias y la terminal son la
prueba.

---

## 1. Reparto del tiempo

| Min | Bloque | Quién | Qué se ve en pantalla |
|---|---|---|---|
| 0:00 – 1:30 | Problema y propuesta: un binario, dos políticas | Integrante 1 | Diapositivas 1–3 |
| 1:30 – 3:00 | Arquitectura, STRIDE y análisis de riesgos | Integrante 1 | Diapositivas 4, 6, 7 |
| 3:00 – 6:30 | **Demostración en vivo**: ataque y mitigación | Integrante 3 | Terminal + panel de evidencias |
| 6:30 – 8:00 | Vulnerabilidades y mitigaciones: la matriz completa | Integrante 2 | Panel, sección «Matriz antes/después» |
| 8:00 – 9:00 | Criptografía y decisiones de implementación | Integrante 2 | Diapositiva 10 y código |
| 9:00 – 10:00 | Roles, riesgos residuales y cierre | Integrante 3 | Diapositiva 13 |

---

## 2. Guion por bloque

### 0:00 – 1:30 · Problema y propuesta (Integrante 1)

> «Una aplicación de gestión documental sin controles permite leer documentos de otros usuarios,
> recuperar credenciales, escalar privilegios y escribir archivos en el servidor sin dejar rastro.
> No lo afirmamos: lo medimos.
>
> Construimos el mismo sistema dos veces, con **un solo binario**: un modo vulnerable con diez
> defectos intencionales y un modo endurecido con sus contramedidas. Mismo esquema de base de datos,
> mismas rutas, mismas pruebas. Cambian solo las decisiones de seguridad.»

Frase de anclaje: *«No comparamos dos proyectos: comparamos dos políticas sobre el mismo código.»*

### 1:30 – 3:00 · Arquitectura, STRIDE y riesgos (Integrante 1)

> «Todo corre en Docker y solo se publica en 127.0.0.1: la base de datos no expone ningún puerto y
> el modo endurecido vive detrás de un gateway con TLS. Sobre el diagrama de flujo aplicamos STRIDE
> y ubicamos cada amenaza en un flujo concreto; después valoramos 12 riesgos con MAGERIT en escala
> 1 a 5. Los cinco riesgos críticos son de control de acceso y de criptografía. Ese orden es el que
> guió la remediación.»

Mostrar: diapositiva 4 (arquitectura), 6 (STRIDE) y 7 (tabla de riesgos).

### 3:00 – 6:30 · Demostración en vivo (Integrante 3)

Preparación previa: laboratorio levantado y panel abierto en `http://127.0.0.1:18090`.

1. **Panel** — mostrar la matriz: nueve ataques, verde en vulnerable (el ataque funcionó), verde en
   endurecido (el ataque fue bloqueado). «Verde en las dos columnas significa cosas opuestas: por eso
   el veredicto se compara contra la expectativa.»

2. **IDOR** (30 s):
   ```bash
   bash attacks/03-idor.sh http://127.0.0.1:18080 vulnerable   # exit 0
   bash attacks/03-idor.sh https://127.0.0.1:18443 hardened     # exit 1
   ```
   > «En el modo vulnerable, Bob lee el contrato confidencial de Alice. En el endurecido, el servidor
   > verifica la propiedad del recurso y responde 403, además de registrar el intento en la auditoría.»

3. **La cookie es el permiso** (30 s): mostrar la petición con `Cookie: sid=alice:admin` y el panel
   administrativo abierto en v1; luego la redirección al login en v2.

4. **Hash débil** (45 s):
   ```bash
   bash attacks/06-weak-hash.sh http://127.0.0.1:18080 vulnerable
   bash attacks/06-weak-hash.sh https://127.0.0.1:18443 hardened
   ```
   > «Tres contraseñas recuperadas con un diccionario de diez palabras. Con Argon2id, cada intento
   > cuesta 19 MiB de memoria: el mismo diccionario no encuentra nada.»

5. **Tráfico en claro** (30 s): abrir `evidence/network/09-http.pcap` en Wireshark (filtro `http`),
   señalar la contraseña legible; abrir `09-tls.pcap` y mostrar que no hay texto legible.

6. **Refrescar la matriz** (15 s): `bash attacks/run-all.sh` → 18 PASS.

> **Plan B:** si falla la red, el proyector o Docker, reproducir el video de la demo
> (`evidence/demo.mp4`) y continuar con el panel, que funciona sin la suite.

### 6:30 – 8:00 · Vulnerabilidades y mitigaciones (Integrante 2)

> «Cada defecto tiene su control en el mismo archivo, a pocas líneas de distancia.»
>
> - SQL concatenado → consulta parametrizada.
> - Salida cruda → escape de salida + CSP + cookie `HttpOnly`.
> - MD5 sin sal → Argon2id con sal única por usuario.
> - Cookie `usuario:rol` → identificador opaco firmado con HMAC-SHA256 + tabla de sesiones.
> - Documentos en claro → AES-256-GCM con nonce aleatorio por documento.
> - Sin límite de intentos → 5 por minuto, bloqueo de 5 minutos, TOTP y `limit_req` en el gateway.
> - Sin trazabilidad → `audit_log` con actor, acción, objetivo y resultado.

### 8:00 – 9:00 · Criptografía (Integrante 2)

> «Tres decisiones que vale la pena defender: el hash usa Argon2id con parámetros de OWASP, no MD5;
> el cifrado es AEAD, así que un documento alterado no se descifra; y la comparación de firmas es en
> tiempo constante para no filtrar información por temporización.»

### 9:00 – 10:00 · Roles, residuales y cierre (Integrante 3)

> «Tres roles: riesgos y arquitectura, desarrollo y endurecimiento, pentesting y evidencias.
>
> Asumimos dos riesgos residuales de nivel medio: una contraseña débil sigue siendo atacable aunque
> el hash sea fuerte —por eso el segundo factor— y la auditoría local no reemplaza un SIEM central.
>
> Todo el trabajo se reproduce con dos comandos. Gracias.»

---

## 3. Checklist técnico 30 minutos antes

```bash
cd ~/Projects/tcc-seguridad
docker compose up -d --build
docker compose --profile tools up -d attacker
bash attacks/run-all.sh                      # debe cerrar en 18 PASS
docker compose restart evidence
xdg-open http://127.0.0.1:18090              # panel listo
xdg-open docs/sustentacion/slides.html       # diapositivas (F = pantalla completa)
```

- [ ] Los cinco contenedores en estado `Up` (`docker compose ps`).
- [ ] Panel abierto y con fecha de la última corrida visible.
- [ ] Wireshark con los dos `.pcap` ya abiertos y filtrados (no improvisar en vivo).
- [ ] Video de respaldo descargado en el equipo, no solo en la nube.
- [ ] Terminal con fuente grande (mínimo 16 pt) y fondo oscuro.
- [ ] Cronómetro: 10 minutos es el límite, no el objetivo.

---

## 4. Preguntas probables y respuestas cortas

| Pregunta | Respuesta |
|---|---|
| ¿Por qué no usaron Kali o VirtualBox como pide el enunciado? | La actividad los menciona como ejemplos de herramientas. Usamos contenedores porque reproducen el 100 % de las pruebas en un equipo de 8 GB de RAM sin instalar nada; además el contenedor `attacker` incluye `tcpdump`, y `sqlmap`, `hydra` y Burp/ZAP funcionan contra los mismos puertos sin cambios. |
| ¿Por qué Rust y no Python? | Seguridad de memoria y un ecosistema criptográfico auditado. Aclaramos que el lenguaje no hace segura a la aplicación: el defecto más grave que encontramos —confiar en el rol que envía el cliente— es de diseño y habría sido idéntico en Python. |
| ¿Cómo saben que la mitigación funciona y no que el ataque está mal escrito? | Porque el mismo script produce resultados opuestos contra dos instancias del mismo binario. Si el ataque estuviera mal escrito, fallaría en las dos. |
| ¿Qué pasa si el atacante tiene acceso a la base de datos? | Con Argon2id obtiene hashes costosos de atacar y los documentos están cifrados con una clave que no vive en la base. Con MD5 obtenía las contraseñas en segundos. |
| ¿Este sistema es seguro ahora? | Es sustancialmente más seguro frente a los nueve ataques probados. Un pentest completo y las recomendaciones del informe (CSRF explícito, anti-repetición de TOTP, análisis de archivos, SIEM) completarían el trabajo. |
| ¿Por qué el riesgo residual de contraseñas sigue en medio? | Porque ningún hash protege de una contraseña predecible: la mitigación real es la política de contraseñas y el segundo factor, que ya está implementado. |
| ¿Corrieron esto contra sistemas reales? | No. Todo el tráfico se genera en una red Docker aislada y solo se publica en 127.0.0.1. Atacar sistemas de la universidad sería un delito según la Ley 1273 de 2009. |

---

## 5. Errores a evitar

1. **Leer las diapositivas.** Se explican, no se leen.
2. **Demostrar sin haber ensayado el orden de las ventanas.** El cambio de terminal al panel cuesta segundos que no sobran.
3. **Decir «es 100 % seguro».** La afirmación correcta es «estos nueve ataques están bloqueados y estos son los riesgos residuales».
4. **Pasar de 10 minutos.** Ensayar dos veces con cronómetro; si se pasa, recortar el bloque de criptografía, nunca la demo.
5. **Improvisar si algo falla.** Si el laboratorio no responde en 20 segundos: video de respaldo y continuar con el panel.
