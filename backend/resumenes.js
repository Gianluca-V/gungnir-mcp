"use strict";
/**
 * Resúmenes calculados de un engagement que muestran el panel y el agente: remediación, tiempo y la capa
 * de ATT&CK Navigator. Reciben las filas ya leídas: no consultan la base.
 */

/** Cómo va la remediación: estados, retests, vencidos y cambios de severidad tras el retest. */
function remediacion(filas, hoy = new Date()) {
  const dia = new Date(hoy); dia.setHours(0, 0, 0, 0);
  const r = {
    total: filas.length,
    por_retest: { not_retested: 0, passed: 0, failed: 0, partial: 0 },
    por_status: { open: 0, in_remediation: 0, fixed: 0, accepted: 0 },
    vencidos: 0,
    diffs: [],
  };
  for (const f of filas) {
    r.por_retest[f.retest_status] = (r.por_retest[f.retest_status] || 0) + 1;
    r.por_status[f.status] = (r.por_status[f.status] || 0) + 1;
    if (f.remediation_due_date && new Date(f.remediation_due_date) < dia && !["fixed", "accepted"].includes(f.status)) r.vencidos++;
    if (f.retest_status !== "not_retested" && f.initial_severity && f.initial_severity !== (f.retest_severity || f.severity))
      r.diffs.push({ id: f.id, title: f.title, de: f.initial_severity, a: f.retest_severity || f.severity });
  }
  return r;
}
const COLUMNAS_REMEDIACION = "id,title,severity,initial_severity,retest_status,retest_severity,status,remediation_due_date,retested_at,risk_accepted_at";

/** Minutos totales, por fase (la custom por su nombre) y por operador. */
function tiempo(filas) {
  const r = { total_minutes: 0, por_fase: {}, por_operador: {} };
  for (const t of filas) {
    r.total_minutes += t.minutes || 0;
    const fase = t.custom_phase_name || t.phase_type || "sin_fase";
    r.por_fase[fase] = (r.por_fase[fase] || 0) + (t.minutes || 0);
    const quien = t.user_name || "-";
    r.por_operador[quien] = (r.por_operador[quien] || 0) + (t.minutes || 0);
  }
  return r;
}

const COLOR_FASE = {
  planning: "#8b5cf6", recon: "#3b82f6", scanning: "#06b6d4",
  exploitation: "#e8192c", post_exploitation: "#f97316", reporting: "#22c55e",
};

/** Capa de ATT&CK Navigator con las técnicas que tienen id de MITRE, una vez cada una: vale la primera que se registró. */
function capaNavigator(titulo, tecnicas) {
  const vistas = new Map();
  for (const t of tecnicas) {
    const k = String(t.mitre_id || "").toUpperCase().trim();
    if (k && !vistas.has(k)) vistas.set(k, t);
  }
  return {
    name: `Gungnir - ${titulo}`.slice(0, 120),
    versions: { attack: "14", navigator: "4.9", layer: "4.5" },
    domain: "enterprise-attack",
    description: "Técnicas ATT&CK ejercidas en el engagement (Gungnir)",
    techniques: [...vistas.entries()].map(([id, t]) => ({
      techniqueID: id,
      color: COLOR_FASE[t.phase_type] || "#e8192c",
      comment: [t.name, t.tactic, t.notes].filter(Boolean).join(" - ").slice(0, 500),
      enabled: true,
    })),
    gradient: { colors: ["#ffffff", "#e8192c"], minValue: 0, maxValue: 100 },
    legendItems: [], showTacticRowBackground: false, hideDisabled: false,
  };
}
const SELECT_TECNICAS_NAVIGATOR = "SELECT mitre_id, name, tactic, phase_type, notes FROM engagement_techniques WHERE engagement_id=? AND mitre_id IS NOT NULL AND mitre_id<>'' ORDER BY added_at, id";

module.exports = { remediacion, COLUMNAS_REMEDIACION, tiempo, capaNavigator, SELECT_TECNICAS_NAVIGATOR };
