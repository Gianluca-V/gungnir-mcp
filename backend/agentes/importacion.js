"use strict";
/**
 * Lectura de escaneos para agentes, con los parsers que ya usa el seguimiento de vulnerabilidades.
 * Solo formatos cuyos resultados tienen un equipo: sin él no se puede controlar el alcance (por eso
 * no están SARIF ni Trivy).
 */
const { PARSERS } = require("../importacion-escaneres");
const formatos = require("../vulnerabilidades-formatos");
const { SEVERIDADES } = require("./hallazgos");
const { evaluar } = require("./alcance");
const { ErrorHttp } = require("./comun");

const FORMATOS = [...Object.keys(PARSERS), "nuclei"];
const TOPE = 300;

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
function aHallazgo(c) {
  const host = c._ip || c._hostname;
  const activo = c._puerto ? `${host.includes(":") ? `[${host}]` : host}:${c._puerto}${/^(tcp|udp|sctp)$/i.test(c._protocolo || "") ? `/${c._protocolo.toLowerCase()}` : ""}` : host;
  const puntaje = Number(c.cvss_score_31);
  return {
    title: corto(c.title, 500), affected_asset: activo, severity: SEVERIDADES.includes(c.severity) ? c.severity : "medium",
    description: corto(c.description, 100000), steps_to_reproduce: corto(c.steps_to_reproduce, 100000), recommendation: corto(c.recommendation, 100000),
    cvss_vector_31: corto(c.cvss_vector_31, 100), cvss_score_31: puntaje > 0 && puntaje <= 10 ? puntaje : null, cwe_id: corto(c.cwe_id, 20),
  };
}

/** Separa lo importable de lo que queda fuera de alcance o por debajo de la severidad pedida. */
function clasificar(crudos, items, minima) {
  const aceptados = [], fuera = new Map();
  let bajoMinimo = 0;
  for (const c of crudos) {
    const hosts = [c._ip, c._hostname].filter(Boolean);
    if (!hosts.length) { fuera.set("(sin equipo)", "El resultado no dice a qué equipo corresponde."); continue; }
    // Alcanza con que la IP o el nombre estén dentro, siempre que ninguno esté excluido.
    const r = hosts.map((h) => evaluar(h, items));
    const excluido = r.find((x) => x.excluido);
    if (excluido || !r.some((x) => x.dentro)) { fuera.set(hosts[0], (excluido || r[0]).motivo); continue; }
    const h = aHallazgo(c);
    if (SEVERIDADES.indexOf(h.severity) > SEVERIDADES.indexOf(minima)) { bajoMinimo++; continue; }
    aceptados.push(h);
  }
  return { aceptados, fuera, bajoMinimo };
}

module.exports = { FORMATOS, TOPE, leer, clasificar };
