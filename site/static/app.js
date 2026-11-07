// Panel de evidencias del TCC.
//  - Renderiza la matriz, el mapa de calor y los riesgos desde los datos generados.
//  - Permite ejecutar los ataques en vivo contra los dos modos.
//  - Amplía los diagramas con zoom y desplazamiento.
// Sin dependencias ni CDN: funciona sin conexión, en el laboratorio local.

const state = {
  resultados: null,
  magerit: null,
  catalogo: null,
  filtro: "todos",
  ejecutando: false,
  saltar: false,
  ritmo: localStorage.getItem("tcc-ritmo") || "normal",
  token: null,
};

// Ritmo del revelado: pausa entre líneas y velocidad de tipeo (ms por carácter).
const RITMOS = {
  calmo: { pausa: 520, letra: 16, minimoFase: 520 },
  normal: { pausa: 210, letra: 6, minimoFase: 220 },
  rapido: { pausa: 30, letra: 0, minimoFase: 40 },
};

function ritmoActual() {
  return RITMOS[state.ritmo] || RITMOS.normal;
}

function esperar(ms) {
  return new Promise((listo) => setTimeout(listo, ms));
}

const NIVELES = [
  { piso: 16, clase: "critico", nombre: "Crítico" },
  { piso: 9, clase: "alto", nombre: "Alto" },
  { piso: 4, clase: "medio", nombre: "Medio" },
  { piso: 0, clase: "bajo", nombre: "Bajo" },
];

function nivelDe(valor) {
  return NIVELES.find((n) => valor >= n.piso) || NIVELES[NIVELES.length - 1];
}

function esc(texto) {
  return String(texto ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function cargarToken() {
  try {
    const respuesta = await fetch("/api/token", { cache: "no-store" });
    state.token = respuesta.ok ? (await respuesta.json()).token : null;
  } catch {
    state.token = null;
  }
}

async function cargarJSON(ruta) {
  const respuesta = await fetch(ruta, { cache: "no-store" });
  if (!respuesta.ok) throw new Error(`${ruta}: HTTP ${respuesta.status}`);
  return respuesta.json();
}

/* ------------------------------------------------------------------ resumen */

function renderResumen(resultados) {
  const contenedor = document.getElementById("resumen");
  const resumen = resultados.summary || { total: 0, pass: 0, fail: 0, skip: 0 };
  const fecha = resultados.generated_at
    ? new Date(resultados.generated_at).toLocaleString("es-CO")
    : "sin ejecuciones";

  contenedor.innerHTML = `
    <div class="chip"><b>${resumen.total}</b><span>ejecuciones</span></div>
    <div class="chip ok"><b>${resumen.pass}</b><span>expectativas cumplidas</span></div>
    <div class="chip bad"><b>${resumen.fail}</b><span>fallos</span></div>
    <div class="chip warn"><b>${resumen.skip}</b><span>omitidas</span></div>
    <div class="chip"><b>${esc(fecha)}</b><span>última corrida</span></div>
  `;
}

/* ------------------------------------------------- demostración en vivo */

function nombreDeAtaque(id) {
  const ataque = (state.resultados?.attacks || []).find((a) => a.id === id);
  return ataque?.name || (state.catalogo?.ejecutables?.[id] ?? id);
}

function renderCatalogo() {
  const contenedor = document.getElementById("catalogo");
  const nota = document.getElementById("catalogo-nota");
  const ejecutables = state.catalogo?.ejecutables || {};

  const ids = Object.keys(ejecutables);
  if (ids.length === 0) {
    contenedor.innerHTML = `<p class="note">No se pudo leer el catálogo de ataques.</p>`;
    return;
  }

  contenedor.innerHTML = ids
    .map(
      (id) => `<button class="boton-ataque" data-id="${esc(id)}" data-modo="vulnerable">
        <span class="flecha">▶</span>
        <span>${esc(nombreDeAtaque(id))}<small>${esc(ejecutables[id])}</small></span>
      </button>`
    )
    .join("");

  contenedor.querySelectorAll(".boton-ataque").forEach((boton) => {
    boton.addEventListener("click", () => {
      document.querySelectorAll(".boton-ataque").forEach((b) => b.classList.remove("activo"));
      boton.classList.add("activo");
      ejecutarAtaque(boton.dataset.id, boton.dataset.modo);
    });
  });

  const soloTerminal = Object.keys(state.catalogo?.solo_terminal || {});
  nota.innerHTML = soloTerminal.length
    ? `${soloTerminal.length} ataques no se ejecutan desde el panel porque necesitan privilegios del host:
       ${soloTerminal.map((id) => `<code>${esc(id)}</code>`).join(", ")}. En la matriz se muestran
       con el comando exacto para correrlos en la terminal.`
    : "";
}

function textoVeredicto(linea) {
  return (linea || "").replace(/^ATAQUE EXITOSO.*/, "exito")
    .replace(/^ATAQUE BLOQUEADO.*/, "bloqueado");
}

function agregarPaso(linea) {
  const fases = document.getElementById("vivo-fases");
  fases.querySelectorAll(".paso.activo").forEach((paso) => {
    paso.classList.remove("activo");
    paso.classList.add("completado");
    const icono = paso.querySelector(".paso-icono");
    if (icono) icono.textContent = "✓";
  });

  const paso = document.createElement("div");
  paso.className = "paso activo";
  paso.innerHTML = `<span class="paso-icono"><span class="aro"></span></span>
    <span class="paso-texto">${esc(linea.texto)}</span>
    <span class="paso-tiempo">${linea.t} ms</span>`;
  fases.appendChild(paso);
  fases.scrollTop = fases.scrollHeight;
}

function agregarConsola(texto, clase) {
  const consola = document.getElementById("vivo-consola");
  consola.querySelectorAll(".note").forEach((n) => n.remove());
  const linea = document.createElement("div");
  linea.className = `lin ${clase}`;
  linea.textContent = texto;
  consola.appendChild(linea);
  consola.scrollTop = consola.scrollHeight;
  return linea;
}

async function agregarConsolaTipeada(texto, clase, velocidad) {
  const consola = document.getElementById("vivo-consola");
  consola.querySelectorAll(".note").forEach((n) => n.remove());
  const linea = document.createElement("div");
  linea.className = `lin ${clase}`;
  consola.appendChild(linea);

  const animar = velocidad > 0 && !state.saltar && texto.length <= 120;
  if (!animar) {
    linea.textContent = texto;
    consola.scrollTop = consola.scrollHeight;
    return;
  }

  linea.classList.add("escribiendo");
  for (let i = 1; i <= texto.length; i += 1) {
    linea.textContent = texto.slice(0, i);
    consola.scrollTop = consola.scrollHeight;
    await esperar(velocidad);
  }
  linea.classList.remove("escribiendo");
}

function actualizarBarra(instantanea) {
  const barra = document.getElementById("vivo-barra");
  const mapa = { preparando: 12, ejecutando: 45, recolectando: 82, interpretando: 92, listo: 100, error: 100 };
  let avance = mapa[instantanea.fase] ?? 10;
  if (instantanea.fase === "ejecutando") {
    avance = Math.min(80, 40 + instantanea.total_lineas * 4);
  }
  barra.style.width = `${avance}%`;
  barra.classList.toggle("corriendo", instantanea.estado === "en_curso");
}

function mostrarVeredicto(instantanea, lineas) {
  const contenedor = document.getElementById("vivo-veredicto");
  const final = [...lineas].reverse().find((l) => l.tipo === "veredicto");
  const clase = final && final.texto.startsWith("ATAQUE EXITOSO")
    ? "exito"
    : final && final.texto.startsWith("ATAQUE BLOQUEADO")
      ? "bloqueado"
      : "raro";
  const segundos = ((instantanea.duracion_ms || 0) / 1000).toFixed(2);

  contenedor.innerHTML = `
    <div class="veredicto-final ${clase}">
      <span class="sello">${esc(final ? final.texto : "SIN VEREDICTO")}</span>
      <span class="medido">exit ${esc(instantanea.exit_code)} · ${segundos} s reales · modo ${esc(instantanea.modo)}</span>
    </div>
    <p class="note">Ese tiempo es el real del ataque. El revelado fue más lento a propósito.</p>`;
}

function limpiarVivo() {
  document.getElementById("vivo-titulo").textContent = "Resultado en vivo";
  document.getElementById("vivo-barra").style.width = "0%";
  document.getElementById("vivo-barra").classList.remove("corriendo");
  document.getElementById("vivo-fases").innerHTML = "";
  document.getElementById("vivo-consola").innerHTML =
    `<p class="note">Todavía no ejecutaste ninguna prueba. Elegí un ataque de la izquierda.</p>`;
  document.getElementById("vivo-veredicto").innerHTML = "";
  document.getElementById("vivo-saltar").hidden = true;
  document.querySelectorAll(".boton-ataque").forEach((b) => b.classList.remove("activo"));
}

async function ejecutarAtaque(id, modo) {
  if (state.ejecutando) return;

  state.ejecutando = true;
  state.saltar = false;

  const titulo = document.getElementById("vivo-titulo");
  const saltar = document.getElementById("vivo-saltar");
  titulo.textContent = `${nombreDeAtaque(id)} · modo ${modo}`;
  document.getElementById("vivo-fases").innerHTML = "";
  document.getElementById("vivo-consola").innerHTML =
    `<p class="note">Iniciando la prueba contra ${esc(state.catalogo?.targets?.[modo] || modo)}…</p>`;
  document.getElementById("vivo-veredicto").innerHTML = "";
  document.getElementById("vivo-barra").style.width = "4%";
  saltar.hidden = false;

  try {
    if (!state.token) await cargarToken();
    const respuesta = await fetch(`/api/run/${encodeURIComponent(id)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Panel-Token": state.token || "" },
      body: JSON.stringify({ mode: modo }),
    });
    const datos = await respuesta.json();

    if (respuesta.status === 409 && datos.comando) {
      document.getElementById("vivo-consola").innerHTML = `
        <div class="barra-resultado"><span class="veredicto-vivo raro">SE EJECUTA EN LA TERMINAL</span></div>
        <p class="explicacion">${esc(datos.error)}.</p>
        <div class="comando-sugerido"><p class="note">Comando para mostrar en vivo:</p>
        <code>${esc(datos.comando)}</code></div>`;
      return;
    }

    if (!respuesta.ok) {
      document.getElementById("vivo-consola").innerHTML = `
        <div class="barra-resultado"><span class="veredicto-vivo raro">ERROR ${respuesta.status}</span></div>
        <p class="explicacion">${esc(datos.error || "respuesta inesperada del servidor")}</p>`;
      return;
    }

    await seguirEjecucion(datos.run_id);
  } catch (error) {
    document.getElementById("vivo-consola").innerHTML =
      `<p class="explicacion">No se pudo contactar al ejecutor: ${esc(error.message)}</p>`;
  } finally {
    state.ejecutando = false;
    saltar.hidden = true;
  }
}

async function seguirEjecucion(runId) {
  let desde = 0;
  let todas = [];
  const ritmo = ritmoActual();

  for (;;) {
    const respuesta = await fetch(`/api/run-progress/${runId}?desde=${desde}`, {
      headers: { "X-Panel-Token": state.token || "" },
      cache: "no-store",
    });
    const instantanea = await respuesta.json();
    if (!respuesta.ok) {
      agregarConsola(instantanea.error || "no se pudo leer el avance", "lin-error");
      return;
    }

    for (const linea of instantanea.lineas) {
      todas.push(linea);
      if (linea.tipo === "fase") {
        agregarPaso(linea);
        if (!state.saltar) await esperar(ritmo.minimoFase);
      } else if (linea.tipo === "veredicto") {
        agregarConsola(linea.texto, "lin-veredicto");
      } else if (linea.tipo === "error") {
        await agregarConsolaTipeada(linea.texto, "lin-error", ritmo.letra);
        if (!state.saltar) await esperar(ritmo.pausa);
      } else {
        await agregarConsolaTipeada(linea.texto, "lin-salida", ritmo.letra);
        if (!state.saltar) await esperar(ritmo.pausa);
      }
    }

    desde = instantanea.total_lineas;
    actualizarBarra(instantanea);

    if (instantanea.estado !== "en_curso") {
      document.querySelectorAll("#vivo-fases .paso.activo").forEach((paso) => {
        paso.classList.remove("activo");
        paso.classList.add("completado");
        const icono = paso.querySelector(".paso-icono");
        if (icono) icono.textContent = "✓";
      });
      mostrarVeredicto(instantanea, todas);
      return;
    }

    await esperar(state.saltar ? 80 : 240);
  }
}

function conectarRitmo() {
  const botones = document.querySelectorAll(".ritmo-btn");
  const marcar = (ritmo) => {
    state.ritmo = ritmo;
    localStorage.setItem("tcc-ritmo", ritmo);
    botones.forEach((b) => b.classList.toggle("activo", b.dataset.ritmo === ritmo));
  };
  marcar(state.ritmo);
  botones.forEach((boton) => boton.addEventListener("click", () => marcar(boton.dataset.ritmo)));

  document.getElementById("vivo-saltar").addEventListener("click", () => {
    state.saltar = true;
  });
}

/* ------------------------------------------------------------ matriz ataques */

function agruparAtaques(ataques) {
  const porId = new Map();
  for (const ataque of ataques) {
    if (!porId.has(ataque.id)) {
      porId.set(ataque.id, { id: ataque.id, name: ataque.name, owasp: ataque.owasp, filas: {} });
    }
    porId.get(ataque.id).filas[ataque.mode] = ataque;
  }
  return [...porId.values()].sort((a, b) => a.id.localeCompare(b.id));
}

function celdaVeredicto(ataque) {
  if (!ataque) return `<span class="note">—</span>`;
  const clase = String(ataque.verdict || "").toLowerCase();
  const etiqueta = ataque.verdict === "PASS" ? "PASS" : ataque.verdict === "FAIL" ? "FAIL" : "SKIP";
  const ejecutable = Object.keys(state.catalogo?.ejecutables || {}).includes(ataque.id);
  const accion = ejecutable
    ? `<button class="veredicto ${clase} ejecutar" data-id="${esc(ataque.id)}" data-modo="${esc(
        ataque.mode
      )}" title="Ejecutar esta prueba en vivo">▶</button>`
    : `<button class="veredicto terminal" data-id="${esc(ataque.id)}" data-modo="${esc(
        ataque.mode
      )}" title="Se ejecuta desde la terminal">⌘</button>`;
  return `${accion} <button class="veredicto ${clase} ver-log" data-id="${esc(ataque.id)}" data-modo="${esc(
    ataque.mode
  )}" title="Ver la salida guardada">${etiqueta}</button>`;
}

function renderTabla() {
  const cuerpo = document.querySelector("#tabla-ataques tbody");
  const ataques = agruparAtaques(state.resultados?.attacks || []);
  if (ataques.length === 0) {
    cuerpo.innerHTML = `<tr><td colspan="5" class="note">Todavía no hay ejecuciones.
      Corré <code>bash attacks/run-all.sh</code> o usá la demostración en vivo.</td></tr>`;
    return;
  }

  cuerpo.innerHTML = ataques
    .map((ataque) => {
      const ocultoV = state.filtro === "endurecido";
      const ocultoH = state.filtro === "vulnerable";
      return `<tr>
        <td class="num">${esc(ataque.id.slice(0, 2))}</td>
        <td><b>${esc(ataque.name)}</b><br><span class="note">${esc(ataque.id)}</span></td>
        <td><span class="note">${esc(ataque.owasp)}</span></td>
        <td class="col-v">${ocultoV ? `<span class="note">—</span>` : celdaVeredicto(ataque.filas.vulnerable)}</td>
        <td class="col-h">${ocultoH ? `<span class="note">—</span>` : celdaVeredicto(ataque.filas.hardened)}</td>
      </tr>`;
    })
    .join("");

  cuerpo.querySelectorAll(".ver-log").forEach((boton) => {
    boton.addEventListener("click", () => mostrarDetalle(boton.dataset.id, boton.dataset.modo));
  });
  cuerpo.querySelectorAll(".ejecutar").forEach((boton) => {
    boton.addEventListener("click", () => {
      document.getElementById("vivo").scrollIntoView({ behavior: "smooth", block: "start" });
      ejecutarAtaque(boton.dataset.id, boton.dataset.modo);
    });
  });
  cuerpo.querySelectorAll(".terminal").forEach((boton) => {
    boton.addEventListener("click", () => {
      document.getElementById("vivo").scrollIntoView({ behavior: "smooth", block: "start" });
      ejecutarAtaque(boton.dataset.id, boton.dataset.modo);
    });
  });
}

async function mostrarDetalle(id, modo) {
  const panel = document.getElementById("detalle");
  const ataque = (state.resultados?.attacks || []).find((a) => a.id === id && a.mode === modo);
  const titulo = document.getElementById("detalle-titulo");
  const meta = document.getElementById("detalle-meta");
  const log = document.getElementById("detalle-log");

  panel.classList.remove("oculto");
  titulo.textContent = `${id} · ${modo}`;
  meta.textContent = ataque
    ? `${ataque.verdict} · ${ataque.name} · ${ataque.owasp} · objetivo ${ataque.target}`
    : "sin datos";
  log.textContent = "cargando…";

  try {
    const respuesta = await fetch(`data/logs/${modo}/${id}.log`, { cache: "no-store" });
    log.textContent = respuesta.ok
      ? await respuesta.text()
      : `No hay log guardado para ${id} en modo ${modo}.`;
  } catch (error) {
    log.textContent = `No se pudo leer el log: ${error.message}`;
  }
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

/* ------------------------------------------------------------------ riesgos */

function renderMapaCalor() {
  const riesgos = state.magerit?.riesgos || [];
  const mapa = document.getElementById("mapa-calor");
  if (!mapa) return;

  const cuenta = new Map();
  for (const riesgo of riesgos) {
    const clave = `${riesgo.frecuencia}-${riesgo.degradacion}`;
    cuenta.set(clave, (cuenta.get(clave) || 0) + 1);
  }

  const celdas = [`<div class="eje"></div>`];
  for (let d = 1; d <= 5; d += 1) celdas.push(`<div class="eje">D=${d}</div>`);

  for (let f = 5; f >= 1; f -= 1) {
    celdas.push(`<div class="eje">F=${f}</div>`);
    for (let d = 1; d <= 5; d += 1) {
      const total = cuenta.get(`${f}-${d}`) || 0;
      const nivel = nivelDe(f * d);
      const clase = total === 0 ? "vacia" : nivel.clase;
      celdas.push(
        `<div class="celda ${clase}" data-f="${f}" data-d="${d}" title="F=${f} · D=${d} · riesgo ${f * d}">${total === 0 ? "·" : total}</div>`
      );
    }
  }
  mapa.innerHTML = celdas.join("");

  mapa.querySelectorAll(".celda:not(.vacia)").forEach((celda) => {
    celda.addEventListener("click", () => {
      mapa.querySelectorAll(".celda").forEach((c) => c.classList.remove("activa"));
      celda.classList.add("activa");
      renderDetalleCelda(Number(celda.dataset.f), Number(celda.dataset.d));
    });
  });

  document.getElementById("mapa-leyenda").innerHTML = NIVELES.map(
    (n) => `<span><i class="celda ${n.clase}" style="width:10px;height:10px;display:inline-block;border:0"></i>${n.nombre}</span>`
  ).join("");
}

function renderDetalleCelda(frecuencia, degradacion) {
  const contenedor = document.getElementById("mapa-detalle");
  const seleccionados = (state.magerit?.riesgos || []).filter(
    (r) => Number(r.frecuencia) === frecuencia && Number(r.degradacion) === degradacion
  );

  if (seleccionados.length === 0) {
    contenedor.innerHTML = `<p class="note">Sin riesgos en esta combinación.</p>`;
    return;
  }

  contenedor.innerHTML = seleccionados
    .map((riesgo) => {
      const nivel = nivelDe(Number(riesgo.riesgo));
      return `<article class="tarjeta-riesgo">
        <header>
          <span class="id">${esc(riesgo.id)} · ${esc(riesgo.activo)}</span>
          <span class="nivel">${nivel.nombre} · ${esc(riesgo.riesgo)}</span>
        </header>
        <p><b>Amenaza:</b> ${esc(riesgo.amenaza)}</p>
        <p><b>Causa:</b> ${esc(riesgo.causa)}</p>
        <p><b>Salvaguarda:</b> ${esc(riesgo.salvaguarda)}</p>
        <p><b>Control:</b> <code>${esc(riesgo.control_v2)}</code></p>
        <p><b>Evidencia:</b> <code>${esc(riesgo.ataque)}</code></p>
      </article>`;
    })
    .join("");
}

function renderTablaRiesgos() {
  const cuerpo = document.querySelector("#tabla-riesgos tbody");
  const riesgos = [...(state.magerit?.riesgos || [])].sort(
    (a, b) => Number(b.riesgo) - Number(a.riesgo)
  );

  document.getElementById("riesgos-meta").textContent =
    `${state.magerit?.metodo || "MAGERIT v3"} · alcance: ${state.magerit?.alcance || "laboratorio"} · ` +
    `${(state.magerit?.activos || []).length} activos · ${riesgos.length} riesgos`;

  if (riesgos.length === 0) {
    cuerpo.innerHTML = `<tr><td colspan="8" class="note">Sin datos de riesgos.</td></tr>`;
    return;
  }

  cuerpo.innerHTML = riesgos
    .map((riesgo) => {
      const nivel = nivelDe(Number(riesgo.riesgo));
      return `<tr>
        <td class="num">${esc(riesgo.id)}</td>
        <td>${esc(riesgo.activo)}</td>
        <td>${esc(riesgo.amenaza)}<br><span class="note">${esc(riesgo.owasp)}</span></td>
        <td class="num">${esc(riesgo.frecuencia)}</td>
        <td class="num">${esc(riesgo.degradacion)}</td>
        <td class="num"><b>${esc(riesgo.riesgo)}</b></td>
        <td><span class="nivel celda ${nivel.clase}" style="display:inline-block;padding:3px 8px;border-radius:99px">${nivel.nombre}</span></td>
        <td>${esc(riesgo.salvaguarda)}<br><span class="note">${riesgo.riesgo_residual ? "residual: " + esc(riesgo.riesgo_residual) : ""}</span></td>
      </tr>`;
    })
    .join("");
}

/* ------------------------------------------------- visor con zoom (diagramas) */

const zoom = { escala: 1, x: 0, y: 0, arrastrando: false, inicioX: 0, inicioY: 0 };

function aplicarTransformacion() {
  const imagen = document.getElementById("lb-imagen");
  imagen.style.transform = `translate(${zoom.x}px, ${zoom.y}px) scale(${zoom.escala})`;
  document.getElementById("lb-zoom").textContent = `${Math.round(zoom.escala * 100)} %`;
}

function reiniciarZoom() {
  zoom.escala = 1;
  zoom.x = 0;
  zoom.y = 0;
  aplicarTransformacion();
}

function cambiarZoom(factor, clientX, clientY) {
  const lienzo = document.getElementById("lb-lienzo");
  const rect = lienzo.getBoundingClientRect();
  const centroX = rect.left + rect.width / 2;
  const centroY = rect.top + rect.height / 2;
  const dx = (clientX ?? centroX) - centroX;
  const dy = (clientY ?? centroY) - centroY;

  const nueva = Math.min(8, Math.max(0.4, zoom.escala * factor));
  // Mantiene fijo el punto bajo el cursor al hacer zoom.
  zoom.x = dx - ((dx - zoom.x) * nueva) / zoom.escala;
  zoom.y = dy - ((dy - zoom.y) * nueva) / zoom.escala;
  zoom.escala = nueva;
  aplicarTransformacion();
}

function abrirLightbox(src, titulo) {
  const caja = document.getElementById("lightbox");
  const imagen = document.getElementById("lb-imagen");
  imagen.src = src;
  document.getElementById("lb-titulo").textContent = titulo || "Diagrama";
  caja.classList.remove("oculto");
  document.body.style.overflow = "hidden";
  reiniciarZoom();
}

function cerrarLightbox() {
  document.getElementById("lightbox").classList.add("oculto");
  document.body.style.overflow = "";
}

function conectarLightbox() {
  document.querySelectorAll("img.ampliable").forEach((imagen) => {
    imagen.addEventListener("click", () =>
      abrirLightbox(imagen.getAttribute("src"), imagen.closest("figure")?.querySelector("figcaption")?.textContent)
    );
  });

  const lienzo = document.getElementById("lb-lienzo");
  document.getElementById("lb-cerrar").addEventListener("click", cerrarLightbox);
  document.getElementById("lb-mas").addEventListener("click", () => cambiarZoom(1.25));
  document.getElementById("lb-menos").addEventListener("click", () => cambiarZoom(0.8));
  document.getElementById("lb-reset").addEventListener("click", reiniciarZoom);
  document.getElementById("lightbox").addEventListener("click", (evento) => {
    if (evento.target.id === "lightbox") cerrarLightbox();
  });

  lienzo.addEventListener(
    "wheel",
    (evento) => {
      evento.preventDefault();
      cambiarZoom(evento.deltaY < 0 ? 1.12 : 0.89, evento.clientX, evento.clientY);
    },
    { passive: false }
  );

  lienzo.addEventListener("dblclick", reiniciarZoom);

  lienzo.addEventListener("mousedown", (evento) => {
    zoom.arrastrando = true;
    zoom.inicioX = evento.clientX - zoom.x;
    zoom.inicioY = evento.clientY - zoom.y;
    lienzo.classList.add("arrastrando");
  });
  window.addEventListener("mousemove", (evento) => {
    if (!zoom.arrastrando) return;
    zoom.x = evento.clientX - zoom.inicioX;
    zoom.y = evento.clientY - zoom.inicioY;
    aplicarTransformacion();
  });
  window.addEventListener("mouseup", () => {
    zoom.arrastrando = false;
    lienzo.classList.remove("arrastrando");
  });

  document.addEventListener("keydown", (evento) => {
    if (document.getElementById("lightbox").classList.contains("oculto")) return;
    if (evento.key === "Escape") cerrarLightbox();
    if (evento.key === "+" || evento.key === "=") cambiarZoom(1.25);
    if (evento.key === "-") cambiarZoom(0.8);
    if (evento.key === "0") reiniciarZoom();
  });
}

/* -------------------------------------------------------------------- setup */

function activarFiltros() {
  document.querySelectorAll(".filtro").forEach((boton) => {
    boton.addEventListener("click", () => {
      document.querySelectorAll(".filtro").forEach((b) => b.classList.remove("activo"));
      boton.classList.add("activo");
      state.filtro = boton.dataset.filtro;
      renderTabla();
    });
  });

  document.getElementById("detalle-cerrar").addEventListener("click", () => {
    document.getElementById("detalle").classList.add("oculto");
  });
  document.getElementById("vivo-limpiar").addEventListener("click", limpiarVivo);
  conectarRitmo();
}

async function iniciar() {
  activarFiltros();
  conectarLightbox();
  await cargarToken();

  try {
    state.catalogo = await cargarJSON("/api/catalogo");
    renderCatalogo();
  } catch (error) {
    document.getElementById("catalogo").innerHTML =
      `<p class="note">El ejecutor en vivo no está disponible (${esc(error.message)}).
       Igual podés consultar las evidencias guardadas.</p>`;
  }

  try {
    state.resultados = await cargarJSON("data/results.json");
    renderResumen(state.resultados);
  } catch (error) {
    document.getElementById("resumen").innerHTML =
      `<div class="chip bad"><b>!</b><span>sin resultados: ${esc(error.message)}</span></div>`;
  }
  renderTabla();

  try {
    state.magerit = await cargarJSON("data/magerit.json");
    renderMapaCalor();
    renderTablaRiesgos();
  } catch (error) {
    document.getElementById("riesgos-meta").textContent =
      `No se pudieron cargar los riesgos: ${error.message}`;
  }
}

document.addEventListener("DOMContentLoaded", iniciar);
