"use strict";
/**
 * Consultas de un agente. Lo que sale de la base pasa por el ocultamiento y viaja dentro de
 * `{ contenido_no_confiable: true, datos }`: es texto que escribieron personas, escáneres o equipos
 * atacados, y quien lo lee tiene que tratarlo como dato y nunca como instrucción.
 */
const path = require("path");
const N = require("./niveles");
const H = require("./hallazgos");
const { evaluador } = require("./alcance");
const { CAMPOS_CLIENTE, nombresDe } = require("./acceso");
const { ErrorHttp, ruta, texto, opcion, entero, recortar } = require("./comun");
const { CATALOGOS } = require("../data/metodologias");

const ARSENAL = require(path.join(__dirname, "..", "data", "arsenal.json"));
const LARGO_CAMPO = 4000;
const LARGO_COMPLETO = 40000;
const LARGO_LISTA = 600;
const ESTADOS_METODOLOGIA = ["pending", "tested", "not_applicable"];

/** Lista guardada como JSON. Lo que no se puede leer cuenta como vacío: una fila mala no rompe el listado. */
function comoLista(v) {
  if (Array.isArray(v)) return v;
  try { const j = JSON.parse(v); return Array.isArray(j) ? j : []; } catch { return []; }
}

function paginar(q) {
  return { limite: entero(q.limite, "limite", { min: 1, max: 100, porDefecto: 25 }), desde: entero(q.desde, "desde", { min: 0, max: 1000000, porDefecto: 0 }) };
}
function recortarObjeto(o, max) {
  return Object.fromEntries(Object.entries(o).map(([k, v]) => [k, recortar(v, max)]));
}
const palabras = (q) => String(q || "").toLocaleLowerCase("es").split(/\s+/).filter(Boolean).slice(0, 10);

function montar(router, { acceso, qRow, qRows, buscarCve }) {
  const con = acceso.conEngagement;
  /** Responde datos guardados: primero se oculta y después se recorta, para no dejar secretos a medias. */
  const entregar = (req, res, datos, { max = LARGO_CAMPO, ...extra } = {}) => {
    const oculto = req.ocultar ? req.ocultar.objeto(datos) : datos;
    const corto = Array.isArray(oculto) ? oculto.map((x) => recortarObjeto(x, max)) : recortarObjeto(oculto, max);
    res.json({ contenido_no_confiable: true, datos_ocultos: Boolean(req.ocultar?.activo), ...extra, datos: corto });
  };
  async function lista(req, res, { sql, params, max = LARGO_LISTA, preparar = (x) => x }) {
    const { limite, desde } = paginar(req.query);
    // LIMIT no admite parámetros preparados en MySQL 8: los dos ya son enteros validados.
    const filas = await qRows(`${sql} LIMIT ${limite + 1} OFFSET ${desde}`, params);
    const hayMas = filas.length > limite;
    entregar(req, res, filas.slice(0, limite).map(preparar), { max, desde, hay_mas: hayMas, siguiente: hayMas ? desde + limite : null });
  }

  router.get("/yo", ruta(async (req, res) => {
    const a = req.agente;
    res.json({ key: a.keyNombre, usuario: a.username, rol: a.rol, nivel_max: a.nivelMax });
  }));

  router.get("/engagements", ruta(async (req, res) => {
    const filas = await qRows(
      `SELECT e.id, e.title, e.type, e.methodology, e.status, e.current_phase, ae.nivel_max, ae.mostrar_sensibles, ${CAMPOS_CLIENTE}
       FROM engagements e
       JOIN agente_key_engagements ke ON ke.engagement_id=e.id AND ke.key_id=?
       JOIN agente_engagements ae ON ae.engagement_id=e.id AND ae.nivel_max<>'ninguno'
       JOIN clients c ON c.id=e.client_id ORDER BY e.updated_at DESC`, [req.agente.keyId]);
    const datos = filas.map((f) => {
      const { id, title, type, methodology, status, current_phase } = f;
      const o = acceso.ocultador({ engagementId: id, nombres: nombresDe(f), activo: !f.mostrar_sensibles });
      return { ...o.objeto({ id, title, type, methodology, status, current_phase }), nivel_efectivo: N.efectivo(req.agente.nivelMax, f.nivel_max, N.techoDeEstado(status)) };
    });
    res.json({ contenido_no_confiable: true, datos });
  }));

  router.get("/engagements/:id", con("lectura"), ruta(async (req, res) => {
    const e = await qRow(
      `SELECT e.id, e.title, e.codename, e.type, e.methodology, e.mode, e.status, e.current_phase, e.start_date, e.end_date,
              e.rules_of_engagement, e.notes, c.name AS cliente
       FROM engagements e JOIN clients c ON c.id=e.client_id WHERE e.id=?`, [req.engagement.id]);
    const fases = await qRows("SELECT phase_type, status FROM phases WHERE engagement_id=? ORDER BY FIELD(phase_type,'planning','recon','scanning','exploitation','post_exploitation','reporting')", [e.id]);
    const sev = await qRows("SELECT severity, COUNT(*) AS n FROM findings WHERE engagement_id=? GROUP BY severity", [e.id]);
    const alcance = await qRow("SELECT SUM(in_scope=1) AS dentro, SUM(in_scope=0) AS fuera FROM scope_items WHERE engagement_id=?", [e.id]);
    entregar(req, res, {
      ...e, fases, hallazgos_por_severidad: Object.fromEntries(sev.map((s) => [s.severity, Number(s.n)])),
      alcance: { dentro: Number(alcance?.dentro || 0), fuera: Number(alcance?.fuera || 0) },
    }, { nivel_efectivo: req.engagement.nivel, max: 12000 });
  }));

  // ── Alcance ─────────────────────────────────────────────────────────────────
  const alcanceDe = (id) => qRows("SELECT type,value,in_scope FROM scope_items WHERE engagement_id=?", [id]);

  router.get("/engagements/:id/alcance", con("lectura"), ruta((req, res) => lista(req, res, {
    sql: "SELECT type, value, in_scope, notes, os_type, ports, pwned FROM scope_items WHERE engagement_id=? ORDER BY in_scope ASC, value, id",
    params: [req.engagement.id],
    preparar: (s) => ({ ...s, in_scope: Boolean(s.in_scope), pwned: Boolean(s.pwned), ports: comoLista(s.ports) }),
  })));

  router.post("/engagements/:id/alcance/verificar", con("lectura"), ruta(async (req, res) => {
    const objetivos = req.body?.objetivos;
    if (!Array.isArray(objetivos) || !objetivos.length || objetivos.length > 100) throw new ErrorHttp(400, `"objetivos" tiene que ser una lista de 1 a 100 textos.`);
    const evaluar = evaluador(await alcanceDe(req.engagement.id));
    const datos = objetivos.map((o) => {
      const objetivo = texto(o, "objetivos", { max: 500, obligatorio: true });
      const { dentro, motivo } = evaluar(objetivo);
      // El motivo puede citar un ítem del alcance, que es texto guardado.
      return { objetivo, dentro, motivo: req.ocultar.texto(motivo, true) };
    });
    res.json({ contenido_no_confiable: true, todos_dentro: datos.every((d) => d.dentro), datos });
  }));

  // ── Hallazgos ───────────────────────────────────────────────────────────────
  router.get("/engagements/:id/hallazgos", con("lectura"), ruta(async (req, res) => {
    const sev = opcion(req.query.severidad, "severidad", H.SEVERIDADES);
    const est = opcion(req.query.estado, "estado", [...H.ESTADOS, "accepted"]);
    const fase = opcion(req.query.fase, "fase", H.FASES);
    const params = [req.engagement.id];
    let sql = "SELECT id,title,severity,status,cvss_score_31,affected_asset,phase_type,created_at FROM findings WHERE engagement_id=?";
    for (const [c, v] of [["severity", sev], ["status", est], ["phase_type", fase]]) if (v) { sql += ` AND ${c}=?`; params.push(v); }
    await lista(req, res, { sql: `${sql} ORDER BY FIELD(severity,'critical','high','medium','low','info'), title, id`, params });
  }));

  router.get("/engagements/:id/hallazgos/:fid", con("lectura"), ruta(async (req, res) => {
    const f = await qRow(`SELECT id, ${H.CAMPOS.join(",")}, created_at, updated_at FROM findings WHERE id=? AND engagement_id=?`, [req.params.fid, req.engagement.id]);
    if (!f) throw new ErrorHttp(404, "El hallazgo no existe en este engagement.");
    entregar(req, res, { ...f, references_list: comoLista(f.references_list) }, { max: req.query.completo === "1" ? LARGO_COMPLETO : LARGO_CAMPO });
  }));

  router.get("/engagements/:id/propuestas", con("lectura"), ruta(async (req, res) => {
    const estado = opcion(req.query.estado, "estado", ["pendiente", "aprobada", "rechazada"]);
    await lista(req, res, {
      sql: `SELECT id, accion, finding_id, estado, motivo, creada_en, JSON_UNQUOTE(JSON_EXTRACT(datos,'$.title')) AS title,
              JSON_UNQUOTE(JSON_EXTRACT(datos,'$.affected_asset')) AS affected_asset, JSON_UNQUOTE(JSON_EXTRACT(datos,'$.severity')) AS severity
            FROM agente_propuestas WHERE engagement_id=? AND key_id=?${estado ? " AND estado=?" : ""} ORDER BY creada_en DESC, id`,
      params: [req.engagement.id, req.agente.keyId, ...(estado ? [estado] : [])],
    });
  }));

  // ── Logs, evidencias y técnicas ─────────────────────────────────────────────
  router.get("/engagements/:id/logs", con("lectura"), ruta(async (req, res) => {
    const fase = opcion(req.query.fase, "fase", H.FASES);
    await lista(req, res, {
      sql: `SELECT id, phase_type, logged_at, target, tool, command, notes, fuera_de_alcance, agente_key_id IS NOT NULL AS por_agente
            FROM operation_logs WHERE engagement_id=?${fase ? " AND phase_type=?" : ""} ORDER BY logged_at DESC, id`,
      params: [req.engagement.id, ...(fase ? [fase] : [])],
      preparar: (l) => ({ ...l, fuera_de_alcance: Boolean(l.fuera_de_alcance), por_agente: Boolean(l.por_agente) }),
    });
  }));

  // Solo los datos del archivo: el contenido puede traer cualquier cosa y no se puede ocultar bien.
  router.get("/engagements/:id/evidencias", con("lectura"), ruta((req, res) => lista(req, res, {
    sql: "SELECT id, finding_id, phase_type, original_name, file_type, file_size, caption, uploaded_at FROM evidences WHERE engagement_id=? ORDER BY uploaded_at DESC, id",
    params: [req.engagement.id],
  })));

  router.get("/engagements/:id/tecnicas", con("lectura"), ruta((req, res) => lista(req, res, {
    sql: "SELECT id, mitre_id, name, tactic, tool, phase_type, notes FROM engagement_techniques WHERE engagement_id=? ORDER BY added_at DESC, id",
    params: [req.engagement.id],
  })));

  // ── Metodología ─────────────────────────────────────────────────────────────
  router.get("/engagements/:id/metodologia", con("lectura"), ruta(async (req, res) => {
    const framework = opcion(req.query.framework, "framework", Object.keys(CATALOGOS)) || "owasp_wstg";
    const estado = opcion(req.query.estado, "estado", ESTADOS_METODOLOGIA);
    const { limite, desde } = paginar(req.query);
    const guardados = new Map((await qRows("SELECT item_key, status, note FROM methodology_checks WHERE engagement_id=? AND framework=?", [req.engagement.id, framework])).map((g) => [g.item_key, g]));
    const todos = CATALOGOS[framework].map((it) => ({ ...it, status: guardados.get(it.key)?.status || "pending", note: guardados.get(it.key)?.note || "" }));
    const resumen = { total: todos.length };
    for (const e of ESTADOS_METODOLOGIA) resumen[e] = todos.filter((t) => t.status === e).length;
    const filtrados = estado ? todos.filter((t) => t.status === estado) : todos;
    const hayMas = desde + limite < filtrados.length;
    entregar(req, res, filtrados.slice(desde, desde + limite), { max: LARGO_LISTA, framework, resumen, desde, hay_mas: hayMas, siguiente: hayMas ? desde + limite : null });
  }));

  // ── Referencia: arsenal, plantillas y CVE ───────────────────────────────────
  router.get("/arsenal", ruta(async (req, res) => {
    const q = palabras(texto(req.query.q, "q", { max: 200 }));
    const fase = opcion(req.query.fase, "fase", ["recon", "scanning", "exploitation", "post_exploitation", "general"]);
    const herramienta = texto(req.query.herramienta, "herramienta", { max: 100 })?.toLocaleLowerCase("es");
    const { limite, desde } = paginar(req.query);
    const cambios = new Map((await qRows("SELECT * FROM cmd_overrides")).map((o) => [o.item_id, o]));
    const propios = await qRows("SELECT id, tool_key AS tool, phase, category, title, command, description, tags, notes, mitre_id AS mitreId FROM arsenal_commands ORDER BY tool_key, created_at");
    const base = ARSENAL.filter((c) => !cambios.get(c.id)?.hidden).map((c) => {
      const o = cambios.get(c.id);
      if (!o) return c;
      const pisado = { title: o.title, command: o.command, description: o.description, phase: o.phase, category: o.category, notes: o.notes, mitreId: o.mitre_id };
      return { ...c, ...Object.fromEntries(Object.entries(pisado).filter(([, v]) => v != null)), ...(o.tags ? { tags: comoLista(o.tags) } : {}) };
    });
    const todos = [...base, ...propios.map((p) => ({ ...p, tags: comoLista(p.tags) }))].filter((c) => {
      if (fase && c.phase !== fase) return false;
      if (herramienta && c.tool.toLocaleLowerCase("es") !== herramienta) return false;
      const en = [c.tool, c.title, c.command, c.description, c.category, c.mitreId, ...(c.tags || [])].join(" ").toLocaleLowerCase("es");
      return q.every((p) => en.includes(p));
    });
    const hayMas = desde + limite < todos.length;
    entregar(req, res, todos.slice(desde, desde + limite), { max: LARGO_LISTA, total: todos.length, desde, hay_mas: hayMas, siguiente: hayMas ? desde + limite : null });
  }));

  router.get("/plantillas", ruta(async (req, res) => {
    const q = texto(req.query.q, "q", { max: 200 });
    const sql = "SELECT id, title, category, severity, cwe_id, owasp_category FROM finding_templates";
    const como = q && `%${q.replace(/[\\%_]/g, "\\$&")}%`;
    await lista(req, res, { sql: `${sql}${q ? " WHERE title LIKE ? OR category LIKE ?" : ""} ORDER BY title, id`, params: q ? [como, como] : [] });
  }));

  router.get("/plantillas/:pid", ruta(async (req, res) => {
    const p = await qRow("SELECT id,title,category,severity,description,steps_to_reproduce,recommendation,cwe_id,cwe_name,owasp_category,cvss_vector_31,cvss_score_31,references_list FROM finding_templates WHERE id=?", [req.params.pid]);
    if (!p) throw new ErrorHttp(404, "La plantilla no existe.");
    entregar(req, res, { ...p, references_list: comoLista(p.references_list) });
  }));

  router.get("/cve/:cve", ruta(async (req, res) => {
    const cve = String(req.params.cve).toUpperCase();
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cve)) throw new ErrorHttp(400, "El formato es CVE-AAAA-NNNN.");
    entregar(req, res, await buscarCve(cve));
  }));
}

module.exports = { montar, ESTADOS_METODOLOGIA };
