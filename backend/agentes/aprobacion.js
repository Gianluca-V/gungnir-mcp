"use strict";
/**
 * Qué hace cada tipo de propuesta al aprobarse. Todos tienen:
 *
 *   validar(datos)              lo editado por la persona, con las mismas reglas que lo propuesto.
 *   objetivos(datos)            lo que tiene que seguir dentro del alcance.
 *   actual(q, p, datos)         lo que hay hoy, para comparar: { actual, cambio, titulo } o null.
 *   aplicar(tx, p, datos, ctx)  lo guarda y devuelve { findingId, despues, resultado }.
 */
const H = require("./hallazgos");
const mapa = require("./mapa");
const retest = require("./retest");
const R = require("../retest");
const { ErrorHttp } = require("./comun");

const comoObjeto = (v) => (typeof v === "string" ? JSON.parse(v) : v);

/** El hallazgo de la propuesta, tomado para escribir. Avisa si cambió después de proponerse. */
async function tomarHallazgo(tx, p, forzar) {
  const f = await tx.qRow("SELECT id, engagement_id, title, severity, status, updated_at >= ? AS cambio FROM findings WHERE id=? AND engagement_id=? FOR UPDATE", [p.creada_en, p.finding_id, p.engagement_id]);
  if (!f) throw new ErrorHttp(409, "El hallazgo que se quería modificar ya no existe.");
  if (p.accion === "retest" && f.status === "accepted") throw retest.aceptado();
  if (f.cambio && !forzar) throw new ErrorHttp(409, "El hallazgo cambió después de la propuesta.", { conflicto: true });
  return f;
}
async function hallazgoActual(q, p, columnas) {
  const f = await q.qRow(`SELECT updated_at >= ? AS cambio, title AS _titulo${columnas.map((k) => `, ${k}`).join("")} FROM findings WHERE id=? AND engagement_id=?`,
    [p.creada_en, p.finding_id, p.engagement_id]);
  return f && { f, cambio: Boolean(f.cambio), titulo: f._titulo };
}

const TIPOS = {
  crear: {
    validar: (d) => H.validar(d, { alta: true }),
    objetivos: (d) => [d.affected_asset],
    actual: async () => null,
    async aplicar(tx, p, datos, { userId }) {
      await tx.qRow("SELECT id FROM engagements WHERE id=? FOR UPDATE", [p.engagement_id]);
      const dup = await tx.qRow("SELECT id FROM findings WHERE engagement_id=? AND title=? AND affected_asset=? AND status<>'fixed' LIMIT 1 FOR UPDATE", [p.engagement_id, datos.title, datos.affected_asset]);
      if (dup) throw new ErrorHttp(409, "Ya existe un hallazgo con ese título y ese activo: rechazá la propuesta.");
      return { findingId: await H.insertar(tx, p.engagement_id, datos, userId) };
    },
  },
  actualizar: {
    validar: (d) => H.validar(d, { alta: false }),
    objetivos: (d) => (d.affected_asset ? [d.affected_asset] : []),
    async actual(q, p, datos) {
      const campos = Object.keys(datos).filter((k) => H.CAMPOS.includes(k));
      const a = await hallazgoActual(q, p, campos);
      return a && { ...a, actual: Object.fromEntries(campos.map((k) => [k, k === "references_list" && a.f[k] ? comoObjeto(a.f[k]) : a.f[k]])) };
    },
    async aplicar(tx, p, datos, { forzar }) {
      await tomarHallazgo(tx, p, forzar);
      await H.modificar(tx, p.engagement_id, p.finding_id, datos);
      return { findingId: p.finding_id };
    },
  },
  retest: {
    validar: (d) => retest.validar(d),
    objetivos: (d) => [d.objetivo],
    async actual(q, p) {
      const a = await hallazgoActual(q, p, ["affected_asset", "retest_status", "retest_severity", "retest_notes"]);
      return a && { ...a, actual: { resultado: a.f.retest_status, objetivo: a.f.affected_asset, retest_severity: a.f.retest_severity, notas: a.f.retest_notes } };
    },
    async aplicar(tx, p, datos, { userId, forzar, deps, persona }) {
      const f = await tomarHallazgo(tx, p, forzar);
      await R.aplicar(tx, f, { result: datos.resultado, retest_severity: datos.retest_severity, notes: datos.notas }, userId);
      return { findingId: f.id, despues: () => R.dejarConstancia(deps, f, datos.resultado, persona) };
    },
  },
  mapa: {
    validar: (d) => mapa.validar(d),
    objetivos: (d) => d.equipos.flatMap(mapa.objetivosDe),
    actual: async () => null,
    async aplicar(tx, p, datos) {
      await tx.qRow("SELECT id FROM engagements WHERE id=? FOR UPDATE", [p.engagement_id]);
      return { findingId: null, resultado: await mapa.aplicar(tx, p.engagement_id, datos) };
    },
  },
};

module.exports = { TIPOS, comoObjeto };
