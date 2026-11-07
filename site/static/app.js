// Panel de evidencias del TCC: renderiza desde los datos que genera build_data.py.
// Sin dependencias ni CDN: funciona sin conexión, en el laboratorio local.

const state = {
  resultados: null,
  magerit: null,
  filtro: "todos",
  celdaActiva: null,
};

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
  return `<button class="veredicto ${clase}" data-id="${esc(ataque.id)}" data-modo="${esc(ataque.mode)}">${etiqueta}</button>`;
}

function renderTabla() {
  const cuerpo = document.querySelector("#tabla-ataques tbody");
  const ataques = agruparAtaques(state.resultados.attacks || []);
  if (ataques.length === 0) {
    cuerpo.innerHTML = `<tr><td colspan="5" class="note">Todavía no hay ejecuciones.
      Corré <code>bash attacks/run-all.sh</code> y reiniciá este panel.</td></tr>`;
    return;
  }

  const visibles = ataques.filter((ataque) => state.filtro === "todos" || true);
  cuerpo.innerHTML = visibles
    .map((ataque) => {
      const vulnerable = ataque.filas.vulnerable;
      const endurecido = ataque.filas.hardened;
      const ocultoV = state.filtro === "endurecido";
      const ocultoH = state.filtro === "vulnerable";
      return `<tr>
        <td class="num">${esc(ataque.id.slice(0, 2))}</td>
        <td><b>${esc(ataque.name)}</b><br><span class="note">${esc(ataque.id)}</span></td>
        <td><span class="note">${esc(ataque.owasp)}</span></td>
        <td class="col-v">${ocultoV ? `<span class="note">—</span>` : celdaVeredicto(vulnerable)}</td>
        <td class="col-h">${ocultoH ? `<span class="note">—</span>` : celdaVeredicto(endurecido)}</td>
      </tr>`;
    })
    .join("");

  cuerpo.querySelectorAll(".veredicto").forEach((boton) => {
    boton.addEventListener("click", () => mostrarDetalle(boton.dataset.id, boton.dataset.modo));
  });
}

async function mostrarDetalle(id, modo) {
  const panel = document.getElementById("detalle");
  const ataque = (state.resultados.attacks || []).find(
    (a) => a.id === id && a.mode === modo
  );
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
  const riesgos = state.magerit.riesgos || [];
  const mapa = document.getElementById("mapa-calor");
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
      const riesgo = f * d;
      const nivel = nivelDe(riesgo);
      const clase = total === 0 ? "vacia" : nivel.clase;
      celdas.push(
        `<div class="celda ${clase}" data-f="${f}" data-d="${d}" title="F=${f} · D=${d} · riesgo ${riesgo}">
           ${total === 0 ? "·" : total}
         </div>`
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
  const seleccionados = (state.magerit.riesgos || []).filter(
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
  const riesgos = [...(state.magerit.riesgos || [])].sort(
    (a, b) => Number(b.riesgo) - Number(a.riesgo)
  );

  document.getElementById("riesgos-meta").textContent =
    `${state.magerit.metodo || "MAGERIT v3"} · alcance: ${state.magerit.alcance || "laboratorio"} · ` +
    `${(state.magerit.activos || []).length} activos · ${riesgos.length} riesgos`;

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
        <td>${esc(riesgo.salvaguarda)}<br><span class="note">${esc(riesgo.riesgo_residual ? "residual: " + riesgo.riesgo_residual : "")}</span></td>
      </tr>`;
    })
    .join("");
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
}

async function iniciar() {
  activarFiltros();
  try {
    state.resultados = await cargarJSON("data/results.json");
    renderResumen(state.resultados);
    renderTabla();
  } catch (error) {
    document.getElementById("resumen").innerHTML =
      `<div class="chip bad"><b>!</b><span>sin resultados: ${esc(error.message)}</span></div>`;
    renderTabla();
  }

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
