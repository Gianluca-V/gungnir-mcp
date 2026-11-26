"use strict";
/**
 * Qué hace cada tipo de propuesta al aprobarse. Todos tienen:
 *
 *   antes(tx, p)                opcional: lo que se bloquea antes de leer nada.
 *   validar(datos)              lo editado por la persona, con las mismas reglas que lo propuesto.
 *   objetivos(datos)            lo que tiene que seguir dentro del alcance.
 *   actual(q, p, datos)         lo que hay hoy, para comparar: { actual, cambio, titulo } o null.
 *   aplicar(tx, p, datos, ctx)  lo guarda y devuelve { findingId, despues, resultado }.
 */
const H = require("./hallazgos");
const mapa = require("./mapa");
const retest = require("./retest");
const S = require("./secciones");
const R = require("../retest");
const { cambiarFase } = require("../fases");
const { ErrorHttp } = require("./comun");

const comoObjeto = (v) => (typeof v === "string" ? JSON.parse(v) : v);

/** Si el hallazgo cambió desde que se propuso. Lo propuesto antes de guardar huella se mira por fecha. */
const cambio = (p, f) => (p.huella ? p.huella !== H.huellaDe(f) : Boolean(f.posterior));
const COLUMNAS = `id, engagement_id, updated_at >= ? AS posterior, ${H.COLUMNAS_HUELLA.join(", ")}`;

/** El hallazgo de la propuesta, tomado para escribir. Avisa si cambió después de proponerse. */
async function tomarHallazgo(tx, p, forzar) {
  const f = await tx.qRow(`SELECT ${COLUMNAS} FROM findings WHERE id=? AND engagement_id=? FOR UPDATE`, [p.creada_en, p.finding_id, p.engagement_id]);
  if (!f) throw new ErrorHttp(409, "El hallazgo que se quería modificar ya no existe.");
  if (p.accion === "retest" && f.status === "accepted") throw retest.aceptado();
  if (cambio(p, f) && !forzar) throw new ErrorHttp(409, "El hallazgo cambió después de la propuesta.", { conflicto: true });
  return f;
}
async function hallazgoActual(q, p) {
  const f = await q.qRow(`SELECT ${COLUMNAS} FROM findings WHERE id=? AND engagement_id=?`, [p.creada_en, p.finding_id, p.engagement_id]);
  return f && { f, cambio: cambio(p, f), titulo: f.title };
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
      const a = await hallazgoActual(q, p);
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
      const a = await hallazgoActual(q, p);
      return a && { ...a, actual: { resultado: a.f.retest_status, objetivo: a.f.affected_asset, retest_severity: a.f.retest_severity, notas: a.f.retest_notes } };
    },
    async aplicar(tx, p, datos, { userId, forzar, deps, persona }) {
      const f = await tomarHallazgo(tx, p, forzar);
      await R.aplicar(tx, f, { result: datos.resultado, retest_severity: datos.retest_severity, notes: datos.notas }, userId);
      return { findingId: f.id, despues: () => R.dejarConstancia(deps, f, datos.resultado, persona) };
    },
  },
  mapa: {
    // Primero: si se leyera algo antes, no se vería lo que otro agente guardó mientras se esperaba.
    antes: (tx, p) => tx.qRow("SELECT id FROM engagements WHERE id=? FOR UPDATE", [p.engagement_id]),
    validar: (d) => mapa.validar(d),
    objetivos: (d) => d.equipos.flatMap(mapa.objetivosDe),
    actual: async (q, p, datos) => ({ actual: { origenes: await mapa.origenesDe(q, p.engagement_id, datos) } }),
    async aplicar(tx, p, datos) {
      return { findingId: null, resultado: await mapa.aplicar(tx, p.engagement_id, datos) };
    },
  },
  fase: {
    validar: (d) => S.validarFase(d),
    objetivos: () => [],
    async actual(q, p) {
      const e = await q.qRow("SELECT current_phase FROM engagements WHERE id=?", [p.engagement_id]);
      return { actual: { fase: e?.current_phase ?? null } };
    },
    async aplicar(tx, p, datos) {
      await tx.qRow("SELECT id FROM engagements WHERE id=? FOR UPDATE", [p.engagement_id]);
      await cambiarFase(tx, p.engagement_id, datos.fase);
      return { findingId: null };
    },
  },
  fase_custom: {
    validar: (d, propuesto) => S.validarFaseCustom(d, propuesto),
    objetivos: () => [],
    async actual(q, p, datos) {
      const f = await q.qRow("SELECT name, work_plan, status FROM custom_phases WHERE id=? AND engagement_id=?", [datos.fase_id, p.engagement_id]);
      return f && { actual: { plan: f.work_plan, estado: f.status }, cambio: p.huella !== S.huellaDeFase(f), titulo: f.name };
    },
    async aplicar(tx, p, datos, { forzar }) {
      const f = await tx.qRow("SELECT id, work_plan, status FROM custom_phases WHERE id=? AND engagement_id=? FOR UPDATE", [datos.fase_id, p.engagement_id]);
      if (!f) throw new ErrorHttp(409, "La fase que se quería modificar ya no existe.");
      if (p.huella !== S.huellaDeFase(f) && !forzar) throw new ErrorHttp(409, "La fase cambió después de la propuesta.", { conflicto: true });
      await S.aplicarFaseCustom(tx, f.id, datos);
      return { findingId: null };
    },
  },
};

module.exports = { TIPOS, comoObjeto };
