"use strict";
/**
 * Rutas del panel para administrar agentes (/api/agentes). Solo con sesión de una persona: una key
 * de agente no pasa por `auth()`, así que no puede aprobar lo que propone ni cambiar su nivel.
 */
const { v4: uuidv4 } = require("uuid");
const N = require("./niveles");
const H = require("./hallazgos");
const { evaluar } = require("./alcance");
const { nuevaKey, hashDeKey } = require("./acceso");
const { ErrorHttp, ruta, texto, opcion, entero } = require("./comun");

const ESCRIBEN = ["admin", "auditor", "pentester"];
const DIAS_POR_DEFECTO = 30;
const DIAS_MAX = 365;

const comoObjeto = (v) => (typeof v === "string" ? JSON.parse(v) : v);

function montar(app, { auth, auditLog, qRow, qRows, qRun, transaccion, notificarHallazgo }) {
  const anotar = (req, accion, entidad, id, detalle) =>
    auditLog(req.user.id, req.user.username, accion, entidad, id, detalle, req.ip);

  async function validarEngagements(ids) {
    if (!Array.isArray(ids) || !ids.length || ids.length > 200 || !ids.every((x) => typeof x === "string"))
      throw new ErrorHttp(400, "Elegí al menos un engagement.");
    const unicos = [...new Set(ids)];
    const filas = await qRows(`SELECT id FROM engagements WHERE id IN (${unicos.map(() => "?").join(",")})`, unicos);
    if (filas.length !== unicos.length) throw new ErrorHttp(400, "Algún engagement no existe.");
    return unicos;
  }
  function validarNivelDeKey(v, rol) {
    const nivel = opcion(v, "nivel_max", N.NIVELES_DE_KEY) || "lectura";
    if (N.efectivo(nivel, N.techoDeRol(rol)) !== nivel) throw new ErrorHttp(403, `Con el rol "${rol}" el nivel máximo es "${N.techoDeRol(rol)}".`);
    return nivel;
  }
  async function keyPropia(req) {
    const k = await qRow("SELECT id, nombre, user_id, revocada_en FROM agente_keys WHERE id=?", [req.params.id]);
    if (!k || (k.user_id !== req.user.id && req.user.role !== "admin")) throw new ErrorHttp(404, "La key no existe.");
    return k;
  }

  // ── Keys ────────────────────────────────────────────────────────────────────
  app.get("/api/agentes/keys", auth(), ruta(async (req, res) => {
    const todas = req.user.role === "admin";
    const keys = await qRows(
      `SELECT k.id, k.nombre, k.prefijo, k.nivel_max, k.expira_en, k.expira_en <= NOW() AS vencida, k.revocada_en, k.ultimo_uso,
              k.creada_en, u.username, k.user_id
       FROM agente_keys k JOIN users u ON u.id=k.user_id ${todas ? "" : "WHERE k.user_id=?"} ORDER BY k.creada_en DESC`,
      todas ? [] : [req.user.id]);
    const uso = await qRows("SELECT ke.key_id, e.id, e.title FROM agente_key_engagements ke JOIN engagements e ON e.id=ke.engagement_id ORDER BY e.title");
    res.json(keys.map((k) => ({
      ...k, vencida: Boolean(k.vencida),
      engagements: uso.filter((x) => x.key_id === k.id).map(({ id, title }) => ({ id, title })),
    })));
  }));

  app.post("/api/agentes/keys", auth(), ruta(async (req, res) => {
    const nombre = texto(req.body.nombre, "nombre", { max: 120, obligatorio: true });
    const nivel = validarNivelDeKey(req.body.nivel_max, req.user.role);
    const dias = entero(req.body.dias, "dias", { min: 1, max: DIAS_MAX, porDefecto: DIAS_POR_DEFECTO });
    const engagements = await validarEngagements(req.body.engagements);
    const key = nuevaKey(), id = uuidv4();
    await transaccion(async (tx) => {
      await tx.qRun(
        "INSERT INTO agente_keys (id,nombre,hash,prefijo,user_id,nivel_max,expira_en) VALUES (?,?,?,?,?,?,DATE_ADD(NOW(), INTERVAL ? DAY))",
        [id, nombre, hashDeKey(key), key.slice(0, 12), req.user.id, nivel, dias]);
      for (const e of engagements) await tx.qRun("INSERT INTO agente_key_engagements (key_id,engagement_id) VALUES (?,?)", [id, e]);
    });
    await anotar(req, "agente_key_crear", "agente_keys", id, `${nombre}: nivel ${nivel}, ${engagements.length} engagement(s), ${dias} días`);
    res.status(201).json({ id, nombre, nivel_max: nivel, key }); // La key se muestra solo acá.
  }));

  app.patch("/api/agentes/keys/:id", auth(), ruta(async (req, res) => {
    const k = await keyPropia(req);
    if (k.revocada_en) throw new ErrorHttp(409, "La key está revocada.");
    const dueno = await qRow("SELECT role FROM users WHERE id=?", [k.user_id]);
    const nivel = req.body.nivel_max === undefined ? null : validarNivelDeKey(req.body.nivel_max, dueno?.role);
    const engagements = req.body.engagements === undefined ? null : await validarEngagements(req.body.engagements);
    if (!nivel && !engagements) throw new ErrorHttp(400, "No hay nada para cambiar.");
    await transaccion(async (tx) => {
      if (nivel) await tx.qRun("UPDATE agente_keys SET nivel_max=? WHERE id=?", [nivel, k.id]);
      if (engagements) {
        await tx.qRun("DELETE FROM agente_key_engagements WHERE key_id=?", [k.id]);
        for (const e of engagements) await tx.qRun("INSERT INTO agente_key_engagements (key_id,engagement_id) VALUES (?,?)", [k.id, e]);
      }
    });
    await anotar(req, "agente_key_cambiar", "agente_keys", k.id, `${k.nombre}: ${[nivel && `nivel ${nivel}`, engagements && `${engagements.length} engagement(s)`].filter(Boolean).join(", ")}`);
    res.json({ ok: true });
  }));

  // Se revoca, no se borra: los logs y las violaciones siguen diciendo qué key los hizo.
  app.delete("/api/agentes/keys/:id", auth(), ruta(async (req, res) => {
    const k = await keyPropia(req);
    await qRun("UPDATE agente_keys SET revocada_en=COALESCE(revocada_en,NOW()) WHERE id=?", [k.id]);
    await anotar(req, "agente_key_revocar", "agente_keys", k.id, k.nombre);
    res.json({ ok: true });
  }));

  // ── Acceso por engagement ───────────────────────────────────────────────────
  app.get("/api/agentes/engagements", auth(), ruta(async (req, res) => {
    const filas = await qRows(
      `SELECT e.id, e.title, e.status, c.name AS client_name, COALESCE(ae.nivel_max,'ninguno') AS nivel_max,
              COALESCE(ae.mostrar_sensibles,0) AS mostrar_sensibles,
              (SELECT COUNT(*) FROM scope_items s WHERE s.engagement_id=e.id AND s.in_scope=1) AS en_alcance
       FROM engagements e JOIN clients c ON c.id=e.client_id LEFT JOIN agente_engagements ae ON ae.engagement_id=e.id
       ORDER BY e.updated_at DESC`);
    res.json(filas.map((f) => ({ ...f, mostrar_sensibles: Boolean(f.mostrar_sensibles) })));
  }));

  app.put("/api/agentes/engagements/:id", auth(["admin", "auditor"]), ruta(async (req, res) => {
    const nivel = opcion(req.body.nivel_max, "nivel_max", N.NIVELES, { obligatorio: true });
    if (typeof req.body.mostrar_sensibles !== "boolean") throw new ErrorHttp(400, `"mostrar_sensibles" tiene que ser verdadero o falso.`);
    const e = await qRow("SELECT id, title FROM engagements WHERE id=?", [req.params.id]);
    if (!e) throw new ErrorHttp(404, "El engagement no existe.");
    await qRun(
      `INSERT INTO agente_engagements (engagement_id,nivel_max,mostrar_sensibles,actualizado_por) VALUES (?,?,?,?)
       ON DUPLICATE KEY UPDATE nivel_max=VALUES(nivel_max), mostrar_sensibles=VALUES(mostrar_sensibles), actualizado_por=VALUES(actualizado_por)`,
      [e.id, nivel, req.body.mostrar_sensibles ? 1 : 0, req.user.id]);
    await anotar(req, "agente_acceso", "engagements", e.id, `${e.title}: nivel ${nivel}, datos sensibles ${req.body.mostrar_sensibles ? "visibles" : "ocultos"}`);
    res.json({ ok: true });
  }));

  // ── Resumen para avisos ─────────────────────────────────────────────────────
  app.get("/api/agentes/resumen", auth(), ruta(async (req, res) => {
    const p = await qRow("SELECT COUNT(*) AS n FROM agente_propuestas WHERE estado='pendiente'");
    const v = await qRow("SELECT COUNT(*) AS n FROM agente_violaciones WHERE revisada_en IS NULL");
    res.json({ propuestas: Number(p.n), violaciones: Number(v.n) });
  }));

  // ── Propuestas ──────────────────────────────────────────────────────────────
  app.get("/api/agentes/propuestas", auth(), ruta(async (req, res) => {
    const estado = opcion(req.query.estado, "estado", ["pendiente", "aprobada", "rechazada"]) || "pendiente";
    const filas = await qRows(
      `SELECT p.*, e.title AS engagement_title, u.username AS decidida_por_nombre, f.title AS hallazgo_actual
       FROM agente_propuestas p JOIN engagements e ON e.id=p.engagement_id
       LEFT JOIN users u ON u.id=p.decidida_por LEFT JOIN findings f ON f.id=p.finding_id
       WHERE p.estado=? ORDER BY p.creada_en DESC LIMIT 500`, [estado]);
    res.json(filas.map((f) => ({ ...f, datos: comoObjeto(f.datos) })));
  }));

  async function aprobar(req, id, forzar) {
    const r = await transaccion(async (tx) => {
      const p = await tx.qRow("SELECT * FROM agente_propuestas WHERE id=? FOR UPDATE", [id]);
      if (!p) throw new ErrorHttp(404, "La propuesta no existe.");
      if (p.estado !== "pendiente") throw new ErrorHttp(409, `La propuesta ya fue ${p.estado}.`);
      const datos = comoObjeto(p.datos);
      if (datos.affected_asset) {
        const a = evaluar(datos.affected_asset, await tx.qRows("SELECT type,value,in_scope FROM scope_items WHERE engagement_id=?", [p.engagement_id]));
        if (!a.dentro) throw new ErrorHttp(409, `El activo ya no está en el alcance: ${a.motivo}`);
      }
      let findingId = p.finding_id;
      if (p.accion === "crear") findingId = await H.insertar(tx, p.engagement_id, datos, req.user.id);
      else {
        const f = await tx.qRow("SELECT updated_at > ? AS cambio FROM findings WHERE id=? AND engagement_id=? FOR UPDATE", [p.creada_en, p.finding_id, p.engagement_id]);
        if (!f) throw new ErrorHttp(409, "El hallazgo que se quería modificar ya no existe.");
        if (f.cambio && !forzar) throw new ErrorHttp(409, "El hallazgo cambió después de la propuesta.", { conflicto: true });
        await H.modificar(tx, p.engagement_id, p.finding_id, datos);
      }
      await tx.qRun("UPDATE agente_propuestas SET estado='aprobada', finding_id=?, decidida_por=?, decidida_en=NOW() WHERE id=?", [findingId, req.user.id, id]);
      return { p, findingId };
    });
    await anotar(req, "agente_propuesta_aprobar", "findings", r.findingId, `Propuesta de la key "${r.p.key_nombre}"`);
    if (r.p.accion === "crear") {
      const f = await qRow("SELECT * FROM findings WHERE id=?", [r.findingId]);
      const e = await qRow("SELECT title AS name FROM engagements WHERE id=?", [r.p.engagement_id]);
      notificarHallazgo(f, e).catch(() => {});
    }
    return r.findingId;
  }

  // Cada propuesta se aprueba en su propia transacción: una con problemas no frena al resto.
  app.post("/api/agentes/propuestas/aprobar-lote", auth(ESCRIBEN), ruta(async (req, res) => {
    const ids = req.body.ids;
    if (!Array.isArray(ids) || !ids.length || ids.length > 300 || !ids.every((x) => typeof x === "string"))
      throw new ErrorHttp(400, `"ids" tiene que ser una lista de 1 a 300 propuestas.`);
    const aprobadas = [], errores = [];
    for (const id of new Set(ids)) {
      try { await aprobar(req, id, false); aprobadas.push(id); } catch (e) {
        if (!(e instanceof ErrorHttp)) throw e;
        errores.push({ id, error: e.message });
      }
    }
    res.json({ aprobadas, errores });
  }));

  app.post("/api/agentes/propuestas/:id/aprobar", auth(ESCRIBEN), ruta(async (req, res) => {
    res.json({ ok: true, finding_id: await aprobar(req, req.params.id, req.body?.forzar === true) });
  }));

  app.post("/api/agentes/propuestas/:id/rechazar", auth(ESCRIBEN), ruta(async (req, res) => {
    const motivo = texto(req.body?.motivo, "motivo", { max: 1000 });
    const [r] = await qRun(
      "UPDATE agente_propuestas SET estado='rechazada', motivo=?, decidida_por=?, decidida_en=NOW() WHERE id=? AND estado='pendiente'",
      [motivo, req.user.id, req.params.id]);
    if (!r.affectedRows) throw new ErrorHttp(409, "La propuesta no existe o ya se decidió.");
    await anotar(req, "agente_propuesta_rechazar", "agente_propuestas", req.params.id, motivo);
    res.json({ ok: true });
  }));

  // ── Violaciones de alcance ──────────────────────────────────────────────────
  app.get("/api/agentes/violaciones", auth(), ruta(async (req, res) => {
    const pendientes = req.query.todas !== "1";
    res.json(await qRows(
      `SELECT v.*, e.title AS engagement_title, l.command, l.tool, l.phase_type, u.username AS revisada_por_nombre
       FROM agente_violaciones v JOIN engagements e ON e.id=v.engagement_id
       LEFT JOIN operation_logs l ON l.id=v.log_id LEFT JOIN users u ON u.id=v.revisada_por
       ${pendientes ? "WHERE v.revisada_en IS NULL" : ""} ORDER BY v.creada_en DESC LIMIT 500`));
  }));

  app.post("/api/agentes/violaciones/:id/revisar", auth(ESCRIBEN), ruta(async (req, res) => {
    const [r] = await qRun("UPDATE agente_violaciones SET revisada_por=?, revisada_en=NOW() WHERE id=? AND revisada_en IS NULL", [req.user.id, req.params.id]);
    if (!r.affectedRows) throw new ErrorHttp(409, "La violación no existe o ya fue revisada.");
    await anotar(req, "agente_violacion_revisar", "agente_violaciones", req.params.id, null);
    res.json({ ok: true });
  }));
}

module.exports = { montar };
