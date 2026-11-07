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
| 0:00 – 1:30 | Problema y propuesta: un binario, dos políticas | Sergio | Diapositivas 1–3 |
| 1:30 – 3:00 | Arquitectura, STRIDE y análisis de riesgos | Sergio | Diapositivas 4, 6, 7 |
| 3:00 – 6:30 | **Demostración en vivo**: ataque y mitigación | Christian | Terminal + panel de evidencias |
| 6:30 – 8:00 | Vulnerabilidades y mitigaciones: la matriz completa | Juan David | Panel, sección «Matriz antes/después» |
| 8:00 – 9:00 | Criptografía y decisiones de implementación | Juan David | Diapositiva 10 y código |
| 9:00 – 10:00 | Roles, riesgos residuales y cierre | Christian | Diapositiva 13 |

---

## 2. Guion por bloque

### 0:00 – 1:30 · Problema y propuesta (Sergio)

> «Una aplicación de gestión documental sin controles permite leer documentos de otros usuarios,
> recuperar credenciales, escalar privilegios y escribir archivos en el servidor sin dejar rastro.
> No lo afirmamos: lo medimos.
>
> Construimos el mismo sistema dos veces, con **un solo binario**: un modo vulnerable con diez
> defectos intencionales y un modo endurecido con sus contramedidas. Mismo esquema de base de datos,
> mismas rutas, mismas pruebas. Cambian solo las decisiones de seguridad.»

Frase de anclaje: *«No comparamos dos proyectos: comparamos dos políticas sobre el mismo código.»*

### 1:30 – 3:00 · Arquitectura, STRIDE y riesgos (Sergio)

> «Todo corre en Docker y solo se publica en 127.0.0.1: la base de datos no expone ningún puerto y
> el modo endurecido vive detrás de un gateway con TLS. Sobre el diagrama de flujo aplicamos STRIDE
> y ubicamos cada amenaza en un flujo concreto; después valoramos 12 riesgos con MAGERIT en escala
> 1 a 5. Los cinco riesgos críticos son de control de acceso y de criptografía. Ese orden es el que
> guió la remediación.»

Mostrar: diapositiva 4 (arquitectura), 6 (STRIDE) y 7 (tabla de riesgos).

### 3:00 – 6:30 · Demostración en vivo (Christian)

Preparación previa: laboratorio levantado y panel abierto en `http://127.0.0.1:18090`.

> La demo se hace **desde el panel**, no desde la terminal: se aprieta ▶, se ve la salida real y se
> explica. La terminal queda como alternativa si algo falla.
>
> Antes de empezar, dejá el ritmo en **Calmo**: el panel muestra las fases (validando → ejecutando →
> recolectando → interpretando) y las líneas de salida con tiempo real. Si vas con el tiempo justo,
> pasá a **Rápido** o usá «ver todo ya».

1. **Apertura del panel** — la primera sección resume el trabajo (problema, qué se hizo, cómo, cómo
   se resolvió) y presenta a los tres integrantes: sirve como portada viva de la sustentación.

2. **Panel** — mostrar la matriz: verde en la columna vulnerable (el ataque funcionó) y verde en la
   columna endurecido (el ataque fue bloqueado). «Verde en las dos columnas significa cosas opuestas:
   por eso el veredicto se compara contra la expectativa.»

2. **IDOR** (40 s): en la fila 03, ▶ en la columna vulnerable → `exit 0`, «bob leyó un documento
   confidencial de alice». Luego ▶ en la columna endurecido → `exit 1`, «el servidor verificó la
   propiedad del recurso». Señalar que cada ejecución guarda su propio directorio temporal y no toca
   las evidencias oficiales.

4. **La cookie es el permiso** (40 s): fila 05, ▶ en vulnerable → panel administrativo; ▶ en
   endurecido → firma inválida. «El servidor confiaba en un valor que el cliente controla.»

5. **El hash es el eslabón débil** (50 s): fila 06, ▶ en vulnerable → tres contraseñas recuperadas con
   un diccionario de diez palabras; ▶ en endurecido → Argon2id no cede. «Cada intento cuesta 19 MiB de
   memoria: eso es lo que hace inviable el ataque a escala.»

6. **Tráfico en claro** (40 s): fila 09 muestra ⌘ (requiere la terminal). Correr el comando que el
   panel indica y abrir `evidence/network/09-http.pcap` en Wireshark con el filtro `http`: la
   contraseña se lee. Abrir `09-tls.pcap`: no hay texto legible.

7. **Refrescar** (15 s): `bash attacks/run-all.sh` en la terminal → 18 PASS, y `docker compose restart
   evidence` si quieren ver la fecha de la corrida actualizada.

> **Plan B:** si falla la red, el proyector o Docker, reproducir el video de la demo
> (`evidence/demo.mp4`) y continuar con el panel, que funciona sin la suite.

### 6:30 – 8:00 · Vulnerabilidades y mitigaciones (Juan David)

> «Cada defecto tiene su control en el mismo archivo, a pocas líneas de distancia.»
>
> - SQL concatenado → consulta parametrizada.
> - Salida cruda → escape de salida + CSP + cookie `HttpOnly`.
> - MD5 sin sal → Argon2id con sal única por usuario.
> - Cookie `usuario:rol` → identificador opaco firmado con HMAC-SHA256 + tabla de sesiones.
> - Documentos en claro → AES-256-GCM con nonce aleatorio por documento.
> - Sin límite de intentos → 5 por minuto, bloqueo de 5 minutos, TOTP y `limit_req` en el gateway.
> - Sin trazabilidad → `audit_log` con actor, acción, objetivo y resultado.

### 8:00 – 9:00 · Criptografía (Juan David)

> «Tres decisiones que vale la pena defender: el hash usa Argon2id con parámetros de OWASP, no MD5;
> el cifrado es AEAD, así que un documento alterado no se descifra; y la comparación de firmas es en
> tiempo constante para no filtrar información por temporización.»

### 9:00 – 10:00 · Roles, residuales y cierre (Christian)

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
./arrancar.sh                              # compila, levanta, verifica 18/18 y abre el panel
xdg-open docs/sustentacion/slides.html     # diapositivas (F = pantalla completa)
```

Si algo quedó raro de una prueba anterior: `./parar.sh --todo && ./arrancar.sh` deja el laboratorio
de cero en dos minutos.

- [ ] Los cinco contenedores en estado `Up` (`docker compose ps`).
- [ ] Panel abierto y con fecha de la última corrida visible.
- [ ] Probado al menos un ataque con el botón ▶ en los dos modos (verifica que el ejecutor en vivo responde).
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
| ¿El panel no es peligroso, si ejecuta comandos? | El ejecutor es local y está acotado: solo responde a `127.0.0.1`, tiene lista blanca de siete ataques, valida el modo, lanza un proceso a la vez con timeout, corre sin shell, exige un token que otra página no puede leer, monta el repositorio en solo lectura y no tiene acceso al socket de Docker; el proceso corre como usuario sin privilegios y el hallazgo de la verificación independiente está documentado en el informe.  Los dos ataques que necesitan privilegios del host no se ejecutan desde el panel: se muestran con su comando. |
| ¿Corrieron esto contra sistemas reales? | No. Todo el tráfico se genera en una red Docker aislada y solo se publica en 127.0.0.1. Atacar sistemas de la universidad sería un delito según la Ley 1273 de 2009. |

---

## 5. Errores a evitar

1. **Leer las diapositivas.** Se explican, no se leen.
2. **Demostrar sin haber ensayado el orden de las ventanas.** El cambio de terminal al panel cuesta segundos que no sobran.
3. **Decir «es 100 % seguro».** La afirmación correcta es «estos nueve ataques están bloqueados y estos son los riesgos residuales».
4. **Pasar de 10 minutos.** Ensayar dos veces con cronómetro; si se pasa, recortar el bloque de criptografía, nunca la demo.
5. **Improvisar si algo falla.** Si el laboratorio no responde en 20 segundos: video de respaldo y continuar con el panel.
