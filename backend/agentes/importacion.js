"use strict";
/**
 * Lectura de escaneos para agentes, con los parsers que ya usa el seguimiento de vulnerabilidades.
 * Solo formatos cuyos resultados tienen un equipo: sin él no se puede controlar el alcance (por eso
 * no están SARIF ni Trivy).
 */
const { PARSERS } = require("../importacion-escaneres");
const formatos = require("../vulnerabilidades-formatos");
const { SEVERIDADES } = require("./hallazgos");
const { evaluador } = require("./alcance");
const { ErrorHttp } = require("./comun");

const FORMATOS = [...Object.keys(PARSERS), "nuclei"];
const TOPE = 300;
const POR_TANDA = 2000;

function leer(formato, contenido) {
  let crudos;
  try {
    crudos = formato === "nuclei" ? formatos.leer("nuclei", contenido).crudos : PARSERS[formato](contenido);
  } catch (e) {
    throw new ErrorHttp(400, `No se pudo leer el archivo como ${formato}: ${e.message}`);
  }
  crudos = (crudos || []).filter((c) => c && c.title);
  if (!crudos.length) throw new ErrorHttp(400, `No se encontraron resultados de ${formato} en el archivo.`);
  return crudos;
}

const corto = (v, n) => (v == null || v === "" ? null : String(v).slice(0, n));
const conPuerto = (host, c) =>
  (c._puerto ? `${host.includes(":") ? `[${host}]` : host}:${c._puerto}${/^(tcp|udp|sctp)$/i.test(c._protocolo || "") ? `/${c._protocolo.toLowerCase()}` : ""}` : host);

/** Las formas de nombrar lo que se encontró, de la más precisa a la menos. */
function activosDe(c) {
  const url = [c._ubicacion, c.affected_asset].find((x) => /^https?:\/\/\S{1,480}$/i.test(x || ""));
  return [url, ...[c._ip, c._hostname].filter(Boolean).map((h) => conPuerto(h, c))].filter(Boolean);
}

function aHallazgo(c, activo) {
  const puntaje = Number(c.cvss_score_31);
  return {
    title: corto(c.title, 500), affected_asset: activo, severity: SEVERIDADES.includes(c.severity) ? c.severity : "medium",
    description: corto(c.description, 100000), steps_to_reproduce: corto(c.steps_to_reproduce, 100000), recommendation: corto(c.recommendation, 100000),
    cvss_vector_31: corto(c.cvss_vector_31, 100), cvss_score_31: puntaje > 0 && puntaje <= 10 ? puntaje : null, cwe_id: corto(c.cwe_id, 20),
  };
}

/** Separa lo importable de lo que queda fuera de alcance o por debajo de la severidad pedida. */
async function clasificar(crudos, items, minima) {
  const aceptados = [], fuera = new Map();
  const evaluar = evaluador(items);
  let bajoMinimo = 0, sinEquipo = 0;
  for (const [n, c] of crudos.entries()) {
    // Se mira todo, sin atajos: un archivo enorme tarda, pero no traba al resto de los pedidos.
    if (n && n % POR_TANDA === 0) await new Promise((ok) => setImmediate(ok));
    const activos = activosDe(c);
    if (!activos.length) { sinEquipo++; continue; }
    // El activo que se guarda es el que está en alcance, con su puerto o su ruta. Alcanza con una forma
    // (URL, IP o nombre), siempre que ninguna esté excluida.
    const r = activos.map((a) => evaluar(a));
    const excluido = r.find((x) => x.excluido);
    const i = r.findIndex((x) => x.dentro);
    if (excluido || i < 0) { fuera.set(c._ip || c._hostname || activos[0], (excluido || r[0]).motivo); continue; }
    const h = aHallazgo(c, activos[i]);
    if (SEVERIDADES.indexOf(h.severity) > SEVERIDADES.indexOf(minima)) { bajoMinimo++; continue; }
    aceptados.push(h);
  }
  return { aceptados, fuera, bajoMinimo, sinEquipo };
}

module.exports = { FORMATOS, TOPE, leer, clasificar };
