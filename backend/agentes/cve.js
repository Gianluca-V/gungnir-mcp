"use strict";
/**
 * Consulta de un CVE en NVD, con memoria de un día, y si se está explotando: KEV (CISA) y EPSS (FIRST).
 * Los hosts son fijos: del agente solo llega el CVE, ya validado.
 */
const { httpRequest, parseJSON } = require("../integrations/http");
const E = require("../vulnerabilidades-enriquecimiento");
const P = require("../vulnerabilidades-prioridad");
const { ErrorHttp } = require("./comun");

const VIGENCIA = 24 * 60 * 60 * 1000;
const TOPE = 500;
const VIEJO = 7 * VIGENCIA;
const EPSS_REINTENTO = 10 * 60 * 1000;
const EPSS_TIEMPO = 8000;

/** Guarda sin pasarse del tope: sale el más viejo. */
function recordar(memoria, clave, valor) {
  if (memoria.size >= TOPE && !memoria.has(clave)) memoria.delete(memoria.keys().next().value);
  memoria.set(clave, valor);
}

function resumir(cve, c) {
  const metrica = [...(c.metrics?.cvssMetricV31 ?? []), ...(c.metrics?.cvssMetricV30 ?? [])][0]?.cvssData;
  return {
    cve,
    publicado: c.published ?? null,
    descripcion: (c.descriptions ?? []).find((d) => d.lang === "es")?.value ?? (c.descriptions ?? []).find((d) => d.lang === "en")?.value ?? "",
    // El panel guarda el vector sin el prefijo de versión.
    cvss_vector_31: metrica?.vectorString?.replace(/^CVSS:3\.\d\//, "") ?? null,
    cvss_score_31: metrica?.baseScore ?? null,
    severity: metrica?.baseSeverity ? String(metrica.baseSeverity).toLowerCase() : null,
    cwe_id: (c.weaknesses ?? []).flatMap((w) => w.description ?? []).find((d) => d.value?.startsWith("CWE-"))?.value ?? null,
    references_list: (c.references ?? []).map((r) => r.url).filter(Boolean).slice(0, 10),
  };
}

function crear({ pedir = httpRequest, ahora = Date.now } = {}) {
  const memoria = new Map();
  return async function buscarCve(cve) {
    const m = memoria.get(cve);
    if (m && ahora() - m.t < VIGENCIA) return m.datos;
    let r;
    try {
      r = await pedir(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`, { timeout: 15000, maxRedirects: 0 });
    } catch { throw new ErrorHttp(503, "No se pudo consultar NVD. Reintentá más tarde."); }
    if (r.status === 403 || r.status === 429) throw new ErrorHttp(503, "NVD limitó las consultas. Esperá 30 segundos y reintentá.");
    if (r.status !== 200 && r.status !== 404) throw new ErrorHttp(503, `NVD respondió ${r.status}.`);
    const lista = r.status === 200 ? parseJSON(r.data)?.vulnerabilities : [];
    // Una página de mantenimiento también llega con 200: no es lo mismo que "no existe".
    if (!Array.isArray(lista)) throw new ErrorHttp(503, "NVD respondió algo que no se pudo leer. Reintentá más tarde.");
    const c = lista[0]?.cve;
    if (!c) throw new ErrorHttp(404, `${cve} no está en NVD.`);
    const datos = resumir(cve, c);
    recordar(memoria, cve, { t: ahora(), datos });
    return datos;
  };
}

/**
 * Si un CVE se está explotando. KEV sale del catálogo que Gungnir baja cada día; EPSS, de lo guardado o de
 * FIRST si falta o quedó viejo. Nunca lanza: lo que no se sabe va como null, con un aviso.
 */
function crearExplotacion({ qRow, descargar = E.descargarTexto, habilitada = E.habilitada, ahora = Date.now }) {
  const memoria = new Map(), enCurso = new Map();

  async function deFirst(cve) {
    const m = memoria.get(cve);
    if (m && ahora() - m.t < (m.fallo ? EPSS_REINTENTO : VIGENCIA)) return m;
    if (!enCurso.has(cve)) enCurso.set(cve, bajar(cve).finally(() => enCurso.delete(cve)));
    return enCurso.get(cve);
  }
  async function bajar(cve) {
    let r;
    try {
      r = { t: ahora(), dato: P.parsearEpss(await descargar(`${E.URL_EPSS}?cve=${encodeURIComponent(cve)}`, { timeout: EPSS_TIEMPO, maxBytes: 200000 })).find((x) => x.cve === cve) ?? null };
    } catch { r = { t: ahora(), dato: null, fallo: true }; }
    recordar(memoria, cve, r);
    return r;
  }
  async function epssDe(cve) {
    const g = await qRow("SELECT epss, percentil, fecha, actualizado FROM vuln_epss WHERE cve=?", [cve]);
    const guardado = g && { epss: Number(g.epss), percentil: g.percentil == null ? null : Number(g.percentil), fecha: P.ymd(g.fecha) };
    if (guardado && ahora() - new Date(g.actualizado).getTime() < VIEJO) return { dato: guardado };
    if (!habilitada()) return { dato: guardado, fallo: !guardado };
    const r = await deFirst(cve);
    return { dato: r.dato ?? guardado, fallo: r.fallo && !guardado };
  }
  async function kevDe(cve) {
    const k = await qRow("SELECT alta, vence, ransomware FROM vuln_kev WHERE cve=?", [cve]);
    if (k) return k;
    // Que no esté solo dice algo si el catálogo es reciente. Cada descarga renueva la fecha de todas las filas.
    const c = await qRow("SELECT COUNT(*) AS n, MAX(actualizado) AS actualizado FROM vuln_kev");
    return Number(c?.n) > 0 && c.actualizado && ahora() - new Date(c.actualizado).getTime() < VIEJO ? false : null;
  }

  return async function explotacion(cve, severidad) {
    const avisos = [];
    const [k, e] = await Promise.all([kevDe(cve).catch(() => null), epssDe(cve).catch(() => ({ dato: null, fallo: true }))]);
    if (k === null) avisos.push("No se sabe si está en KEV: el catálogo no está descargado o es viejo.");
    if (e.fallo) avisos.push("No se pudo obtener EPSS.");
    const epss = e.dato?.epss ?? null;
    return {
      kev: k === null ? null : Boolean(k), ...(k ? { kev_desde: P.ymd(k.alta), kev_vence: P.ymd(k.vence), ransomware: Number(k.ransomware) === 1 ? true : null } : {}),
      epss, epss_percentil: e.dato?.percentil ?? null, epss_fecha: e.dato?.fecha ?? null,
      prioridad: k || severidad ? P.prioridad({ severidad, epss, kev: k ? 1 : 0 }) : null,
      ...(avisos.length ? { avisos } : {}),
    };
  };
}

module.exports = { crear, crearExplotacion };
