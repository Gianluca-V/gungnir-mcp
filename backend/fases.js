"use strict";
/** Fase activa de un engagement. La usan la ruta del panel y lo que hace o propone un agente. */
const FASES = ["planning", "recon", "scanning", "exploitation", "post_exploitation", "reporting"];

/**
 * Deja `fase` como activa. Un engagement planificado pasa a en curso; lo entregado o archivado queda igual.
 * La fase pasa a en curso salvo que ya esté terminada.
 */
async function cambiarFase({ qRun }, engagementId, fase) {
  await qRun(
    "UPDATE engagements SET current_phase=?, status=IF(status IN ('planned'), 'in_progress', status) WHERE id=?",
    [fase, engagementId]
  );
  await qRun(
    "UPDATE phases SET status=IF(status='completed', 'completed', 'in_progress'), started_at=COALESCE(started_at, NOW()) WHERE engagement_id=? AND phase_type=?",
    [engagementId, fase]
  );
}

module.exports = { FASES, cambiarFase };
