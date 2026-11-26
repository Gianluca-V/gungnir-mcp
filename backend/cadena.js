"use strict";
/**
 * Cadena de ataque: relaciones entre hallazgos de un engagement (uno habilita, escala o pivota a otro).
 * La usan la ruta del panel y lo que hace o propone un agente.
 *
 * Es un grafo sin ciclos: una cadena que vuelve a su origen no explica cómo se llegó. Cada alta toma el
 * engagement antes de mirar, así dos altas a la vez no pueden cerrar un ciclo entre las dos.
 */
const { v4: uuidv4 } = require("uuid");
const { ErrorHttp, ruta, texto, opcion } = require("./agentes/comun");

const RELACIONES = ["enables", "escalates", "pivots"];
const MAX_NOTA = 5000;

async function crearTablas({ qRun }) {
  await qRun(`CREATE TABLE IF NOT EXISTS finding_links (
    id VARCHAR(36) PRIMARY KEY,
    engagement_id VARCHAR(36) NOT NULL,
    from_finding_id VARCHAR(36) NOT NULL,
    to_finding_id VARCHAR(36) NOT NULL,
    relation ENUM('enables','escalates','pivots') NOT NULL,
    notes TEXT NULL,
    created_by VARCHAR(36) NULL,
    agente_key_id VARCHAR(36) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_par (from_finding_id, to_finding_id),
    INDEX idx_eng (engagement_id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (from_finding_id) REFERENCES findings(id) ON DELETE CASCADE,
    FOREIGN KEY (to_finding_id) REFERENCES findings(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
}

/** Si ya hay un camino de `desde` a `hasta`: sumar hasta→desde cerraría un ciclo. */
async function hayCamino(q, engagementId, desde, hasta) {
  const links = await q.qRows("SELECT from_finding_id AS a, to_finding_id AS b FROM finding_links WHERE engagement_id=?", [engagementId]);
  const salen = new Map();
  for (const { a, b } of links) salen.set(a, [...(salen.get(a) || []), b]);
  const vistos = new Set([desde]);
  for (const pendientes = [desde]; pendientes.length;) {
    const x = pendientes.pop();
    if (x === hasta) return true;
    for (const y of salen.get(x) || []) if (!vistos.has(y)) { vistos.add(y); pendientes.push(y); }
  }
  return false;
}

/**
 * Controla que la relación se pueda sumar y devuelve los títulos de los dos hallazgos.
 * Toma el engagement: `q` tiene que ser una transacción.
 */
async function comprobar(q, engagementId, { origen, destino }) {
  if (origen === destino) throw new ErrorHttp(400, "Un hallazgo no se relaciona consigo mismo.");
  await q.qRow("SELECT id FROM engagements WHERE id=? FOR UPDATE", [engagementId]);
  const fs = await q.qRows("SELECT id, title FROM findings WHERE engagement_id=? AND id IN (?,?)", [engagementId, origen, destino]);
  const titulo = (id) => fs.find((f) => f.id === id)?.title;
  if (!titulo(origen) || !titulo(destino)) throw new ErrorHttp(404, "Algún hallazgo no existe en este engagement.");
  if (await q.qRow("SELECT id FROM finding_links WHERE from_finding_id=? AND to_finding_id=?", [origen, destino]))
    throw new ErrorHttp(409, "Esa relación ya existe en la cadena.");
  if (await hayCamino(q, engagementId, destino, origen))
    throw new ErrorHttp(409, "La relación cerraría un ciclo: el destino ya lleva al origen en la cadena.");
  return { origen_titulo: titulo(origen), destino_titulo: titulo(destino) };
}

/** Suma la relación, después de comprobarla. */
async function crear(q, engagementId, { origen, destino, relacion, nota }, { userId, keyId = null }) {
  const titulos = await comprobar(q, engagementId, { origen, destino });
  const id = uuidv4();
  await q.qRun("INSERT INTO finding_links (id,engagement_id,from_finding_id,to_finding_id,relation,notes,created_by,agente_key_id) VALUES (?,?,?,?,?,?,?,?)",
    [id, engagementId, origen, destino, relacion, nota ?? null, userId, keyId]);
  return { id, ...titulos };
}

const SELECT_LINKS = `SELECT l.id, l.from_finding_id, l.to_finding_id, l.relation, l.notes, l.agente_key_id IS NOT NULL AS created_by_agent, l.created_at,
  a.title AS from_title, b.title AS to_title
  FROM finding_links l JOIN findings a ON a.id=l.from_finding_id JOIN findings b ON b.id=l.to_finding_id
  WHERE l.engagement_id=?`;

function montar(app, { auth, auditLog, qRow, qRows, transaccion, ESCRIBEN }) {
  app.get("/api/engagements/:id/attack-chain", auth(), ruta(async (req, res) => {
    const e = await qRow("SELECT id FROM engagements WHERE id=?", [req.params.id]);
    if (!e) throw new ErrorHttp(404, "No encontrado");
    const [findings, links, techniques] = await Promise.all([
      qRows("SELECT id, title, severity, status, affected_asset, phase_type FROM findings WHERE engagement_id=? ORDER BY FIELD(severity,'critical','high','medium','low','info'), title", [e.id]),
      qRows(`${SELECT_LINKS} ORDER BY l.created_at, l.id`, [e.id]),
      qRows("SELECT id, name, mitre_id, tactic, phase_type FROM engagement_techniques WHERE engagement_id=? ORDER BY phase_type, name", [e.id]),
    ]);
    res.json({ findings, links: links.map((l) => ({ ...l, created_by_agent: Boolean(l.created_by_agent) })), techniques });
  }));

  app.post("/api/engagements/:id/attack-chain", auth(ESCRIBEN), ruta(async (req, res) => {
    const b = req.body || {};
    const d = {
      origen: texto(b.from_finding_id, "from_finding_id", { max: 36, obligatorio: true }),
      destino: texto(b.to_finding_id, "to_finding_id", { max: 36, obligatorio: true }),
      relacion: opcion(b.relation, "relation", RELACIONES, { obligatorio: true }),
      nota: texto(b.notes, "notes", { max: MAX_NOTA }),
    };
    const r = await transaccion(async (tx) => {
      if (!(await tx.qRow("SELECT id FROM engagements WHERE id=?", [req.params.id]))) throw new ErrorHttp(404, "No encontrado");
      return crear(tx, req.params.id, d, { userId: req.user.id });
    });
    await auditLog(req.user.id, req.user.username, "attack_chain_link", "engagements", req.params.id, `${r.origen_titulo} → ${d.relacion} → ${r.destino_titulo}`.slice(0, 2000), req.ip);
    res.status(201).json({ id: r.id });
  }));

  app.delete("/api/engagements/:id/attack-chain/:linkId", auth(ESCRIBEN), ruta(async (req, res) => {
    const l = await qRow(`${SELECT_LINKS} AND l.id=?`, [req.params.id, req.params.linkId]);
    if (!l) throw new ErrorHttp(404, "La relación no existe en este engagement.");
    await transaccion((tx) => tx.qRun("DELETE FROM finding_links WHERE id=?", [l.id]));
    await auditLog(req.user.id, req.user.username, "attack_chain_unlink", "engagements", req.params.id, `${l.from_title} → ${l.relation} → ${l.to_title}`.slice(0, 2000), req.ip);
    res.json({ ok: true });
  }));
}

module.exports = { RELACIONES, MAX_NOTA, crearTablas, comprobar, crear, montar, SELECT_LINKS };
