"use strict";
/** Consulta de un CVE en NVD, con memoria de un día. El host es fijo: del agente solo llega el CVE, ya validado. */
const { httpRequest, parseJSON } = require("../integrations/http");
const { ErrorHttp } = require("./comun");

const VIGENCIA = 24 * 60 * 60 * 1000;
const TOPE = 500;

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
    const c = r.status === 200 ? parseJSON(r.data)?.vulnerabilities?.[0]?.cve : null;
    if (r.status !== 200 && r.status !== 404) throw new ErrorHttp(503, `NVD respondió ${r.status}.`);
    if (!c) throw new ErrorHttp(404, `${cve} no está en NVD.`);
    const datos = resumir(cve, c);
    if (memoria.size >= TOPE) memoria.delete(memoria.keys().next().value);
    memoria.set(cve, { t: ahora(), datos });
    return datos;
  };
}

module.exports = { crear };
