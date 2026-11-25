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
const TOPE_LECTURA = 20000;

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

const severidadDe = (c) => (SEVERIDADES.includes(c.severity) ? c.severity : "medium");
const bajoLaMinima = (severidad, minima) => SEVERIDADES.indexOf(severidad) > SEVERIDADES.indexOf(minima);

function aHallazgo(c, activo) {
  const puntaje = Number(c.cvss_score_31);
  return {
    title: corto(c.title, 500), affected_asset: activo, severity: severidadDe(c),
    description: corto(c.description, 100000), steps_to_reproduce: corto(c.steps_to_reproduce, 100000), recommendation: corto(c.recommendation, 100000),
    cvss_vector_31: corto(c.cvss_vector_31, 100), cvss_score_31: puntaje > 0 && puntaje <= 10 ? puntaje : null, cwe_id: corto(c.cwe_id, 20),
  };
}

/** Deja pasar lo que cumple `siempre` y, del resto, un resultado por equipo. */
function unoPorEquipo(crudos, siempre = () => false) {
  const equipos = new Set();
  return crudos.filter((c) => {
    if (siempre(c)) return true;
    const equipo = c._ip || c._hostname || activosDe(c)[0];
    return !equipos.has(equipo) && equipos.add(equipo);
  });
}

/** Separa lo importable de lo que queda fuera de alcance o por debajo de la severidad pedida. */
function clasificar(crudos, items, minima) {
  const aceptados = [], fuera = new Map();
  const evaluar = evaluador(items);
  // En un archivo enorme, de lo que no llega a la severidad pedida se mira un resultado por equipo. Si igual
  // se pasa, se va a rechazar: alcanza con saber qué equipos estaban fuera de alcance.
  const acotados = crudos.length <= TOPE_LECTURA ? crudos : unoPorEquipo(crudos, (c) => !bajoLaMinima(severidadDe(c), minima));
  const excede = acotados.length > TOPE_LECTURA ? acotados.length : 0;
  let bajoMinimo = crudos.length - acotados.length, sinEquipo = 0;
  for (const c of excede ? unoPorEquipo(acotados).slice(0, TOPE_LECTURA) : acotados) {
    const activos = activosDe(c);
    if (!activos.length) { sinEquipo++; continue; }
    // El activo que se guarda es el que está en alcance, con su puerto o su ruta. Alcanza con una forma
    // (URL, IP o nombre), siempre que ninguna esté excluida.
    const r = activos.map((a) => evaluar(a));
    const excluido = r.find((x) => x.excluido);
    const i = r.findIndex((x) => x.dentro);
    if (excluido || i < 0) { fuera.set(c._ip || c._hostname || activos[0], (excluido || r[0]).motivo); continue; }
    const h = aHallazgo(c, activos[i]);
    if (bajoLaMinima(h.severity, minima)) { bajoMinimo++; continue; }
    aceptados.push(h);
  }
  return { aceptados, fuera, bajoMinimo, sinEquipo, excede };
}

module.exports = { FORMATOS, TOPE, TOPE_LECTURA, leer, clasificar };
