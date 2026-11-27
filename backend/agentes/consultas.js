"use strict";
/**
 * Consultas del agente sobre módulos de Gungnir fuera del engagement en sí: vulnerabilidades del seguimiento
 * continuo, tiempo cargado, capa de ATT&CK Navigator, notas, documentos de fases custom, recon pasivo,
 * Exploit-DB y papers propios. Todo es de lectura y viaja como contenido no confiable.
 *
 * Lo que no es del engagement se limita a lo que el agente ya puede ver: vulnerabilidades del mismo cliente
 * y de activos en alcance, y notas o papers del dueño de la key, nunca los compartidos por otra persona.
 */
const resumenes = require("../resumenes");
const { evaluador } = require("./alcance");
const { ErrorHttp, ruta, texto, opcion } = require("./comun");

const SEVERIDADES = ["critical", "high", "medium", "low", "info"];
const ESTADOS_VULN = ["abierto", "en_remediacion", "remediado", "reabierto", "riesgo_aceptado", "falso_positivo"];
const TOPE_VULNS = 5000;
const LARGO_LISTA = 600;
const LARGO_CAMPO = 4000;
const LARGO_COMPLETO = 40000;

/** Un activo se ve si alguno de sus nombres está en alcance y ninguno está excluido. */
function enAlcance(evaluar, ...nombres) {
  const r = nombres.filter(Boolean).map((n) => evaluar(String(n)));
  return r.some((x) => x.dentro) && !r.some((x) => x.excluido || x.exclusionIlegible);
}

function montar(router, { acceso, auditLog, qRow, qRows, consultarRecon, buscarEnExploitdb, entregar, lista, paginar }) {
  const con = acceso.conEngagement;
  const alcanceDe = async (id) => evaluador(await qRows("SELECT type,value,in_scope FROM scope_items WHERE engagement_id=?", [id]));
  const como = (q) => `%${q.replace(/[\\%_]/g, "\\$&")}%`;

  // ── Vulnerabilidades del seguimiento continuo ───────────────────────────────
  router.get("/engagements/:id/vulnerabilidades", con("lectura"), ruta(async (req, res) => {
    const sev = opcion(req.query.severidad, "severidad", SEVERIDADES);
    const est = opcion(req.query.estado, "estado", ESTADOS_VULN);
    const q = texto(req.query.q, "q", { max: 200 });
    const { limite, desde } = paginar(req.query);
    const e = await qRow("SELECT client_id FROM engagements WHERE id=?", [req.engagement.id]);
    const params = [e.client_id];
    let sql = `SELECT v.id, v.titulo, v.severidad, v.cvss, v.cves, v.cwe, v.puerto, v.protocolo, v.servicio, v.ubicacion, v.estado, v.fuente,
        v.prioridad, v.epss, v.kev, DATE_FORMAT(v.fecha_limite,'%Y-%m-%d') AS fecha_limite, v.primera_vez, v.ultima_vez, v.engagement_id, v.finding_id,
        a.nombre AS activo, a.ip AS activo_ip, a.hostname AS activo_hostname
      FROM vuln_hallazgos v JOIN activos a ON a.id=v.activo_id AND a.eliminado_at IS NULL WHERE v.cliente_id=?`;
    for (const [c, v] of [["v.severidad", sev], ["v.estado", est]]) if (v) { sql += ` AND ${c}=?`; params.push(v); }
    if (q) { sql += " AND (v.titulo LIKE ? OR v.cves LIKE ? OR a.nombre LIKE ? OR a.ip LIKE ? OR a.hostname LIKE ?)"; params.push(...Array(5).fill(como(q))); }
    const filas = await qRows(`${sql} ORDER BY FIELD(v.severidad,'critical','high','medium','low','info'), v.primera_vez, v.id LIMIT ${TOPE_VULNS}`, params);
    const evaluar = await alcanceDe(req.engagement.id);
    const visibles = filas.filter((v) => enAlcance(evaluar, v.activo_ip, v.activo_hostname))
      .map((v) => ({ ...v, kev: Boolean(v.kev), ya_en_este_engagement: v.engagement_id === req.engagement.id, engagement_id: undefined }));
    const hayMas = desde + limite < visibles.length;
    entregar(req, res, visibles.slice(desde, desde + limite), { max: LARGO_LISTA, desde, hay_mas: hayMas, siguiente: hayMas ? desde + limite : null });
  }));

  // ── Tiempo y Navigator ──────────────────────────────────────────────────────
  router.get("/engagements/:id/tiempo", con("lectura"), ruta(async (req, res) => {
    const filas = await qRows(
      `SELECT te.id, te.phase_type, te.custom_phase_id, cp.name AS custom_phase_name, te.minutes, te.note, DATE_FORMAT(te.worked_on,'%Y-%m-%d') AS worked_on,
              COALESCE(u.full_name, u.username) AS user_name, te.user_id=? AS mio
       FROM time_entries te LEFT JOIN users u ON u.id=te.user_id LEFT JOIN custom_phases cp ON cp.id=te.custom_phase_id
       WHERE te.engagement_id=? ORDER BY te.worked_on DESC, te.created_at DESC, te.id`, [req.agente.userId, req.engagement.id]);
    const { limite, desde } = paginar(req.query);
    const hayMas = desde + limite < filas.length;
    entregar(req, res, filas.slice(desde, desde + limite).map((t) => ({ ...t, mio: Boolean(t.mio) })),
      { max: LARGO_LISTA, resumen: req.ocultar.objeto(resumenes.tiempo(filas)), desde, hay_mas: hayMas, siguiente: hayMas ? desde + limite : null });
  }));

  router.get("/engagements/:id/navigator", con("lectura"), ruta(async (req, res) => {
    const capa = resumenes.capaNavigator(req.engagement.titulo, await qRows(resumenes.SELECT_TECNICAS_NAVIGATOR, [req.engagement.id]));
    res.json({ contenido_no_confiable: true, datos: req.ocultar.objeto(capa) });
  }));

  // ── Notas propias del dueño de la key ───────────────────────────────────────
  router.get("/engagements/:id/notas", con("lectura"), ruta((req, res) => lista(req, res, {
    sql: "SELECT id, title, content, tags, is_pinned, created_at, updated_at FROM notes WHERE user_id=? AND engagement_id=? ORDER BY is_pinned DESC, updated_at DESC, id",
    params: [req.agente.userId, req.engagement.id],
    preparar: (n) => ({ ...n, is_pinned: Boolean(n.is_pinned), tags: etiquetas(n.tags) }),
  })));

  router.get("/engagements/:id/notas/:nid", con("lectura"), ruta(async (req, res) => {
    const n = await qRow("SELECT id, title, content, tags, is_pinned, created_at, updated_at FROM notes WHERE id=? AND user_id=? AND engagement_id=?",
      [req.params.nid, req.agente.userId, req.engagement.id]);
    if (!n) throw new ErrorHttp(404, "La nota no existe entre las tuyas de este engagement.");
    entregar(req, res, { ...n, is_pinned: Boolean(n.is_pinned), tags: etiquetas(n.tags) }, { max: req.query.completo === "1" ? LARGO_COMPLETO : LARGO_CAMPO });
  }));

  // ── Documentos de fases custom ──────────────────────────────────────────────
  // Solo los datos del archivo, como las evidencias: el contenido no se puede ocultar bien.
  router.get("/engagements/:id/documentos", con("lectura"), ruta((req, res) => lista(req, res, {
    sql: `SELECT * FROM (
        SELECT d.id, 'documento' AS tipo, d.phase_id AS fase_custom, NULL AS actualizacion_id, d.original_name, d.file_type, d.file_size, d.caption, d.uploaded_at
        FROM custom_phase_docs d WHERE d.engagement_id=?
        UNION ALL
        SELECT i.id, 'imagen', u.phase_id, i.update_id, i.original_name, NULL, i.file_size, NULL, i.uploaded_at
        FROM custom_phase_update_images i JOIN custom_phase_updates u ON u.id=i.update_id JOIN custom_phases p ON p.id=u.phase_id WHERE p.engagement_id=?
      ) x ORDER BY uploaded_at DESC, id`,
    params: [req.engagement.id, req.engagement.id],
  })));

  // ── Recon pasivo ────────────────────────────────────────────────────────────
  // Consulta servicios de terceros (Shodan, RDAP, crt.sh, DNS), no al objetivo. Igual exige alcance:
  // fuera de él no se consulta a nadie.
  router.post("/engagements/:id/recon", con("lectura"), ruta(async (req, res) => {
    const objetivo = texto(req.body?.objetivo, "objetivo", { max: 255, obligatorio: true });
    const a = (await alcanceDe(req.engagement.id))(objetivo);
    if (!a.dentro) throw new ErrorHttp(422, `No se consultó: el objetivo está fuera de alcance. ${req.ocultar.texto(a.motivo, true)}`);
    const datos = await consultarRecon(objetivo);
    await auditLog(req.agente.userId, req.agente.username, "agente_recon", "engagements", req.engagement.id, `[key ${req.agente.keyNombre}] ${objetivo}`.slice(0, 2000), req.ip);
    res.json({ contenido_no_confiable: true, datos: req.ocultar.objeto(datos) });
  }));

  // ── Referencia: Exploit-DB y papers propios ─────────────────────────────────
  router.get("/exploitdb", ruta(async (req, res) => {
    const q = texto(req.query.q, "q", { max: 120, obligatorio: true });
    if (q.length < 2) throw new ErrorHttp(400, `"q" necesita al menos 2 caracteres.`);
    let r;
    try { r = await buscarEnExploitdb(q); } catch (e) { throw new ErrorHttp(502, `No se pudo consultar Exploit-DB: ${e.message}`); }
    if (r.error) throw new ErrorHttp(502, r.error);
    const { limite, desde } = paginar(req.query);
    const hayMas = desde + limite < r.papers.length;
    res.json({ contenido_no_confiable: true, total: r.total, desde, hay_mas: hayMas, siguiente: hayMas ? desde + limite : null,
      datos: r.papers.slice(desde, desde + limite).map(({ edb_id, ...p }) => ({ ...p, url: `https://www.exploit-db.com/papers/${edb_id}` })) });
  }));

  router.get("/papers", ruta(async (req, res) => {
    const q = texto(req.query.q, "q", { max: 200 });
    await lista(req, res, {
      sql: `SELECT id, title, category, tags, authors, date, cve_id, cvss_score, status, updated_at FROM papers WHERE user_id=?${q ? " AND (title LIKE ? OR tags LIKE ? OR cve_id LIKE ?)" : ""} ORDER BY updated_at DESC, id`,
      params: [req.agente.userId, ...(q ? Array(3).fill(como(q)) : [])],
    });
  }));

  router.get("/papers/:pid", ruta(async (req, res) => {
    const p = await qRow("SELECT * FROM papers WHERE id=? AND user_id=?", [req.params.pid, req.agente.userId]);
    if (!p) throw new ErrorHttp(404, "El paper no existe entre los tuyos.");
    const { user_id, ...datos } = p;
    entregar(req, res, datos, { max: req.query.completo === "1" ? LARGO_COMPLETO : LARGO_CAMPO });
  }));
}

/** Etiquetas guardadas como JSON. Lo que no se puede leer cuenta como ninguna. */
function etiquetas(v) {
  if (Array.isArray(v)) return v;
  try { const j = JSON.parse(v); return Array.isArray(j) ? j : []; } catch { return []; }
}

module.exports = { montar, enAlcance, ESTADOS_VULN };
