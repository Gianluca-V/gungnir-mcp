"use strict";
/** Reprueba de un hallazgo. La usan la ruta del panel y la aprobación de lo que propone un agente. */
const RESULTADOS = ["passed", "failed", "partial"];
const SEVERIDADES = ["critical", "high", "medium", "low", "info"];
const ESTADO = { passed: "fixed", failed: "open", partial: "in_remediation" };

/** `f` es el hallazgo actual. Con "passed" la severidad queda en info; si no se indica otra, en la que tenía. */
async function aplicar({ qRun }, f, { result, retest_severity, notes }, userId) {
  const severidad = result === "passed" ? "info" : SEVERIDADES.includes(retest_severity) ? retest_severity : f.severity;
  await qRun(
    `UPDATE findings SET retest_status=?, retest_severity=?, retest_notes=?,
      retested_at=NOW(), retested_by=?, status=? WHERE id=?`,
    [result, severidad, notes || null, userId, ESTADO[result], f.id]
  );
}

/** Lo que sigue a guardarla: la auditoría y el historial de la vulnerabilidad continua (no la cierra). */
async function dejarConstancia({ qRows, qRun, auditLog }, f, result, { id, username, ip }) {
  await auditLog(id, username, "finding_retest", "engagements", f.engagement_id, `${String(f.title).slice(0,60)} → ${result}`, ip);
  await require("./vulnerabilidades-engagement").registrarRetest({ qRows, qRun }, f.id, result, username);
}

module.exports = { RESULTADOS, aplicar, dejarConstancia };
