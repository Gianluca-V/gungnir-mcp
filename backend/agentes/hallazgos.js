"use strict";
/** Alta y modificación de hallazgos para agentes: campos permitidos, validación y escritura. */
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { ErrorHttp, texto, opcion, tieneRecorte } = require("./comun");
const { tieneMarcas } = require("./ocultar");

const FASES = ["planning", "recon", "scanning", "exploitation", "post_exploitation", "reporting"];
const SEVERIDADES = ["critical", "high", "medium", "low", "info"];
const LARGO = 100000;

// "accepted" no está: aceptar un riesgo lo decide una persona.
const ESTADOS = ["open", "in_remediation", "fixed"];
const OPCIONES = {
  severity: SEVERIDADES,
  business_risk: ["high", "medium", "low"],
  exploitability: ["proven", "functional", "poc", "theoretical"],
  phase_type: FASES,
  status: ESTADOS,
};
const TEXTOS = {
  title: 500, description: LARGO, steps_to_reproduce: LARGO, affected_asset: 500,
  cvss_vector_31: 100, cvss_vector_40: 200, cwe_id: 20, cwe_name: 200, owasp_category: 100, owasp_year: 10,
  mitre_tactic: 100, mitre_technique_id: 20, mitre_technique_name: 200,
  recommendation: LARGO, executive_summary: 20000,
};
const PUNTAJES = ["cvss_score_31", "cvss_score_40"];
const CAMPOS = [...Object.keys(TEXTOS), ...Object.keys(OPCIONES), ...PUNTAJES, "references_list"];

function exigirSinMarcas(v) {
  if (tieneMarcas(v)) throw new ErrorHttp(400, "El texto contiene marcas [OCULTO:...]. Guardarlas pisaría el dato real: quitá ese campo o reescribilo sin la marca.");
  if (tieneRecorte(v)) throw new ErrorHttp(400, "El texto contiene una marca [RECORTADO:...]. Guardarlo perdería el resto: pedí el campo completo o no lo envíes.");
}

/** Valida lo que llega y devuelve solo los campos permitidos que vinieron. */
function validar(b, { alta }) {
  if (!b || typeof b !== "object" || Array.isArray(b)) throw new ErrorHttp(400, "Falta el cuerpo del hallazgo.");
  const desconocidos = Object.keys(b).filter((k) => !CAMPOS.includes(k));
  if (desconocidos.length) throw new ErrorHttp(400, `Campos no admitidos: ${desconocidos.join(", ")}. Se admiten: ${CAMPOS.join(", ")}.`);
  const d = {};
  for (const [k, max] of Object.entries(TEXTOS))
    if (b[k] !== undefined) d[k] = texto(b[k], k, { max, obligatorio: ["title", "affected_asset"].includes(k) });
  for (const [k, ops] of Object.entries(OPCIONES)) if (b[k] !== undefined) d[k] = opcion(b[k], k, ops, { obligatorio: k !== "phase_type" });
  for (const k of PUNTAJES) {
    if (b[k] === undefined) continue;
    if (b[k] !== null && (typeof b[k] !== "number" || !(b[k] >= 0 && b[k] <= 10))) throw new ErrorHttp(400, `"${k}" tiene que ser un número entre 0 y 10.`);
    d[k] = b[k];
  }
  if (b.references_list !== undefined) {
    const r = b.references_list;
    if (!Array.isArray(r) || r.length > 50 || !r.every((x) => typeof x === "string" && x.length <= 1000))
      throw new ErrorHttp(400, `"references_list" tiene que ser una lista de hasta 50 textos.`);
    d.references_list = r;
  }
  if (alta) for (const k of ["title", "affected_asset"]) if (!d[k]) throw new ErrorHttp(400, `"${k}" es obligatorio.`);
  if (!alta && !Object.keys(d).length) throw new ErrorHttp(400, "No hay ningún campo para modificar.");
  exigirSinMarcas(d);
  return d;
}

// Lo que, si cambia, hace que una propuesta sobre el hallazgo se tenga que mirar de nuevo.
const COLUMNAS_HUELLA = [...CAMPOS, "remediation_due_date", "retest_status", "retest_severity", "retest_notes", "retested_at", "risk_accepted_reason", "risk_accepted_at"];
// Una fecha se toma como está guardada, no en la zona horaria del servidor.
const fijo = (v) => (v instanceof Date ? [v.getFullYear(), v.getMonth(), v.getDate(), v.getHours(), v.getMinutes(), v.getSeconds()] : v ?? null);
const huellaDe = (f) => crypto.createHash("sha256").update(JSON.stringify(COLUMNAS_HUELLA.map((k) => fijo(f[k])))).digest("hex");

const aColumna = (k, v) => (k === "references_list" && v ? JSON.stringify(v) : v ?? null);

async function insertar(tx, engagementId, datos, userId) {
  const id = uuidv4();
  const d = { severity: "medium", business_risk: "medium", exploitability: "theoretical", status: "open", ...datos };
  const fila = { id, engagement_id: engagementId, ...d, initial_severity: d.severity, created_by: userId };
  const k = Object.keys(fila);
  await tx.qRun(`INSERT INTO findings (${k.join(",")}) VALUES (${k.map(() => "?").join(",")})`, k.map((c) => aColumna(c, fila[c])));
  return id;
}

async function modificar(tx, engagementId, findingId, datos) {
  const k = Object.keys(datos);
  await tx.qRun(`UPDATE findings SET ${k.map((c) => `${c}=?`).join(",")} WHERE id=? AND engagement_id=?`,
    [...k.map((c) => aColumna(c, datos[c])), findingId, engagementId]);
}

/** Un hallazgo abierto, o una propuesta pendiente, con el mismo título y activo. */
async function buscarDuplicado(q, engagementId, { title, affected_asset }) {
  const f = await q.qRow(
    "SELECT id FROM findings WHERE engagement_id=? AND title=? AND affected_asset=? AND status<>'fixed' LIMIT 1",
    [engagementId, title, affected_asset]);
  if (f) return { tipo: "hallazgo", id: f.id };
  const p = await q.qRow(
    `SELECT id FROM agente_propuestas WHERE engagement_id=? AND estado='pendiente' AND accion='crear'
       AND JSON_UNQUOTE(JSON_EXTRACT(datos,'$.title'))=? AND JSON_UNQUOTE(JSON_EXTRACT(datos,'$.affected_asset'))=? LIMIT 1`,
    [engagementId, title, affected_asset]);
  return p ? { tipo: "propuesta", id: p.id } : null;
}

async function proponer(tx, { engagementId, agente, accion, findingId = null, datos, huella = null }) {
  const id = uuidv4();
  await tx.qRun(
    "INSERT INTO agente_propuestas (id,engagement_id,key_id,key_nombre,accion,finding_id,datos,huella) VALUES (?,?,?,?,?,?,?,?)",
    [id, engagementId, agente.keyId, agente.keyNombre, accion, findingId, JSON.stringify(datos), huella]);
  return id;
}

module.exports = { FASES, SEVERIDADES, ESTADOS, CAMPOS, COLUMNAS_HUELLA, huellaDe, validar, exigirSinMarcas, insertar, modificar, buscarDuplicado, proponer };
