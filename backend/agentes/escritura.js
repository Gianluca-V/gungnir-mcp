"use strict";
/**
 * Lo que un agente registra, crea, modifica o borra.
 *
 * El alcance del engagement no se toca desde acá en ningún nivel: un agente que pudiera ampliarlo
 * se habilitaría solo.
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const N = require("./niveles");
const H = require("./hallazgos");
const importacion = require("./importacion");
const { evaluar } = require("./alcance");
const { ErrorHttp, ruta, texto, opcion } = require("./comun");
const { CATALOGOS } = require("../data/metodologias");

// El tipo sale de la extensión, no de lo que declara quien sube. Sin HTML ni SVG: ejecutan código
// al abrirse. Un XML también puede traerlos adentro, así que se guarda como texto.
const TIPOS = {
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
  ".pdf": "application/pdf", ".txt": "text/plain", ".log": "text/plain", ".md": "text/plain", ".csv": "text/csv",
  ".xml": "text/plain", ".nessus": "text/plain", ".json": "application/json", ".jsonl": "text/plain", ".zip": "application/zip",
};
const MB = 1024 * 1024;
const VENTANA_EN_CURSO_MIN = 10;
const TOPE_VIOLACIONES = 50;

function montar(router, { acceso, auditLog, qRow, qRun, transaccion, notificar, carpeta }) {
  const con = acceso.conEngagement;
  const subida = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * MB, files: 1, fields: 20 } });
  const recibir = (req, res, next) => subida.single("archivo")(req, res, (e) => {
    if (!e) return next();
    res.status(e.code === "LIMIT_FILE_SIZE" ? 413 : 400).json({ error: e.code === "LIMIT_FILE_SIZE" ? "El archivo supera los 20 MB." : "La subida no es válida." });
  });

  const anotar = (req, accion, entidad, id, detalle) =>
    auditLog(req.agente.userId, req.agente.username, `agente_${accion}`, entidad, id, `[key ${req.agente.keyNombre}] ${detalle || ""}`.slice(0, 2000), req.ip);
  /** Pone en fila las altas de un engagement, para que dos iguales a la vez no pasen el control de duplicados. */
  const enFila = (tx, id) => tx.qRow("SELECT id FROM engagements WHERE id=? FOR UPDATE", [id]);
  const alcanceDe = (q, id) => q.qRows("SELECT type,value,in_scope FROM scope_items WHERE engagement_id=?", [id]);

  // Adentro de una transacción solo se usa su conexión: pedir otra al pool puede trabarlo entero.
  async function violacion(q, req, { tipo, logId = null, objetivo, motivo }) {
    await q.qRun("INSERT INTO agente_violaciones (id,engagement_id,key_id,key_nombre,tipo,log_id,objetivo,motivo) VALUES (?,?,?,?,?,?,?,?)",
      [uuidv4(), req.engagement.id, req.agente.keyId, req.agente.keyNombre, tipo, logId, String(objetivo).slice(0, 500), String(motivo).slice(0, 1000)]);
    req.violaciones = [...(req.violaciones || []), `${tipo}: ${objetivo}`];
  }

  /**
   * Corre `fn(tx)` en una transacción y responde lo que devuelve: { codigo, cuerpo, despues }.
   * Con `Idempotency-Key`, un reintento recibe la misma respuesta sin volver a escribir: la respuesta
   * se guarda en la misma transacción que los datos, así no puede quedar una cosa sin la otra.
   */
  const escribir = (fn) => ruta(async (req, res) => {
    const clave = texto(req.headers["idempotency-key"], "Idempotency-Key", { max: 100 });
    let huella = null;
    if (clave) {
      huella = crypto.createHash("sha256").update(JSON.stringify([req.method, req.originalUrl, req.body ?? null]))
        .update(req.file ? req.file.buffer : "").update(req.file?.originalname || "").digest("hex");
      const previa = await reservar(req.agente.keyId, clave, huella);
      if (previa) { res.set("Idempotency-Replayed", "true"); return res.status(previa.codigo).json(previa.cuerpo); }
    }
    let r;
    try {
      r = await transaccion(async (tx) => {
        const out = await fn(req, tx);
        if (clave) await tx.qRun("UPDATE agente_idempotencia SET lista=1, codigo=?, respuesta=? WHERE key_id=? AND clave=?", [out.codigo, JSON.stringify(out.cuerpo), req.agente.keyId, clave]);
        return out;
      });
    } catch (e) {
      // La transacción se deshizo: los archivos que alcanzó a guardar no quedan sueltos.
      for (const a of req.archivosEscritos || []) await fs.promises.unlink(path.join(carpeta, a)).catch(() => {});
      req.violaciones = [];
      await sinFallar("registrar lo rechazado", async () => {
        // Lo rechazado por alcance deja constancia aunque el pedido se haya deshecho.
        for (const v of e.violaciones || []) await violacion({ qRun }, req, v);
        await anotarViolaciones(req);
      });
      if (clave) await sinFallar("liberar la clave", () => qRun("DELETE FROM agente_idempotencia WHERE key_id=? AND clave=? AND lista=0", [req.agente.keyId, clave]));
      throw e;
    }
    // Ya está guardado: lo que falle desde acá no cambia la respuesta, o el agente repetiría el pedido.
    await sinFallar("auditar", async () => {
      await anotarViolaciones(req);
      if (r.despues) await r.despues();
    });
    res.status(r.codigo).json(r.cuerpo);
  });

  async function sinFallar(que, fn) {
    try { await fn(); } catch (e) { console.error(`[GUNGNIR] Agentes: no se pudo ${que}:`, e.message); }
  }
  async function anotarViolaciones(req) {
    for (const v of req.violaciones || []) await anotar(req, "fuera_de_alcance", "engagements", req.engagement.id, v);
  }

  async function reservar(keyId, clave, huella) {
    await qRun("DELETE FROM agente_idempotencia WHERE creada_en < NOW() - INTERVAL 7 DAY OR (key_id=? AND clave=? AND lista=0 AND creada_en < NOW() - INTERVAL ? MINUTE)", [keyId, clave, VENTANA_EN_CURSO_MIN]);
    const [r] = await qRun("INSERT IGNORE INTO agente_idempotencia (key_id,clave,huella) VALUES (?,?,?)", [keyId, clave, huella]);
    if (r.affectedRows) return null;
    const p = await qRow("SELECT huella, lista, codigo, respuesta FROM agente_idempotencia WHERE key_id=? AND clave=?", [keyId, clave]);
    if (p && p.huella !== huella) throw new ErrorHttp(422, "Esa Idempotency-Key ya se usó con otro contenido.");
    if (!p || !p.lista) throw new ErrorHttp(409, "El mismo pedido todavía se está procesando. Reintentá en unos segundos.", { en_curso: true });
    return { codigo: p.codigo, cuerpo: JSON.parse(p.respuesta) };
  }

  // ── Logs ────────────────────────────────────────────────────────────────────
  router.post("/engagements/:id/logs", con("propuesta"), escribir(async (req, tx) => {
    const b = req.body || {};
    H.exigirSinMarcas(b);
    const fase = opcion(b.fase, "fase", H.FASES, { obligatorio: true });
    const objetivo = texto(b.objetivo, "objetivo", { max: 500 });
    const herramienta = texto(b.herramienta, "herramienta", { max: 100 });
    const comando = texto(b.comando, "comando", { max: 10000 });
    const notas = texto(b.notas, "notas", { max: 20000 });
    if (!comando && !notas) throw new ErrorHttp(400, `Falta "comando" o "notas".`);
    if (comando && !objetivo) throw new ErrorHttp(400, `Un log con "comando" necesita "objetivo": así se controla el alcance.`);
    const a = objetivo ? evaluar(objetivo, await alcanceDe(tx, req.engagement.id)) : { dentro: true, motivo: null };
    const id = uuidv4();
    await tx.qRun(
      "INSERT INTO operation_logs (id,engagement_id,phase_type,target,tool,command,notes,created_by,agente_key_id,fuera_de_alcance) VALUES (?,?,?,?,?,?,?,?,?,?)",
      [id, req.engagement.id, fase, objetivo, herramienta, comando, notas, req.agente.userId, req.agente.keyId, a.dentro ? 0 : 1]);
    await tx.qRun("UPDATE phases SET status=IF(status='not_started','in_progress',status), started_at=COALESCE(started_at,NOW()) WHERE engagement_id=? AND phase_type=?", [req.engagement.id, fase]);
    if (!a.dentro) await violacion(tx, req, { tipo: "log", logId: id, objetivo, motivo: a.motivo });
    return {
      codigo: 201,
      cuerpo: { id, fuera_de_alcance: !a.dentro, ...(a.dentro ? {} : { alerta: `VIOLACIÓN DE ALCANCE registrada: ${req.ocultar.texto(a.motivo, true)} Detené las acciones sobre ese objetivo y avisá a la persona a cargo.` }) },
    };
  }));

  // ── Hallazgos ───────────────────────────────────────────────────────────────
  const exigirActivoEnAlcance = async (tx, req, activo) => {
    const a = evaluar(activo, await alcanceDe(tx, req.engagement.id));
    if (a.dentro) return;
    const e = new ErrorHttp(422, `El hallazgo se rechazó por alcance: ${req.ocultar.texto(a.motivo, true)} "affected_asset" tiene que ser un host, IP, host:puerto o URL dentro de alcance.`);
    e.violaciones = [{ tipo: "hallazgo", objetivo: activo, motivo: a.motivo }];
    throw e;
  };

  router.post("/engagements/:id/hallazgos", con("propuesta"), escribir(async (req, tx) => {
    const datos = H.validar(req.body, { alta: true });
    await enFila(tx, req.engagement.id);
    await exigirActivoEnAlcance(tx, req, datos.affected_asset);
    const dup = await H.buscarDuplicado(tx, req.engagement.id, datos);
    if (dup) throw new ErrorHttp(409, `Ya existe ${dup.tipo === "hallazgo" ? "un hallazgo" : "una propuesta pendiente"} con ese título y ese activo.`, { existente: dup });
    if (!N.alcanza(req.engagement.nivel, "escritura")) {
      const id = await H.proponer(tx, { engagementId: req.engagement.id, agente: req.agente, accion: "crear", datos });
      return { codigo: 202, cuerpo: { propuesta_id: id, estado: "pendiente", aviso: "Queda a la espera de que una persona lo apruebe en el panel." },
        despues: () => anotar(req, "propuesta", "agente_propuestas", id, datos.title) };
    }
    const id = await H.insertar(tx, req.engagement.id, datos, req.agente.userId);
    return { codigo: 201, cuerpo: { hallazgo_id: id }, despues: async () => {
      await anotar(req, "hallazgo_crear", "findings", id, datos.title);
      await notificar(id, req.engagement.titulo);
    } };
  }));

  router.put("/engagements/:id/hallazgos/:fid", con("propuesta"), escribir(async (req, tx) => {
    const datos = H.validar(req.body, { alta: false });
    const f = await tx.qRow("SELECT id, title, status FROM findings WHERE id=? AND engagement_id=? FOR UPDATE", [req.params.fid, req.engagement.id]);
    if (!f) throw new ErrorHttp(404, "El hallazgo no existe en este engagement.");
    if (f.status === "accepted" && datos.status) throw new ErrorHttp(409, "Una persona aceptó el riesgo de este hallazgo: su estado no se cambia desde acá.");
    if (datos.affected_asset) await exigirActivoEnAlcance(tx, req, datos.affected_asset);
    if (!N.alcanza(req.engagement.nivel, "escritura")) {
      const id = await H.proponer(tx, { engagementId: req.engagement.id, agente: req.agente, accion: "actualizar", findingId: f.id, datos });
      return { codigo: 202, cuerpo: { propuesta_id: id, estado: "pendiente", aviso: "El cambio queda a la espera de aprobación." },
        despues: () => anotar(req, "propuesta", "agente_propuestas", id, `cambio en ${f.title}`) };
    }
    await H.modificar(tx, req.engagement.id, f.id, datos);
    return { codigo: 200, cuerpo: { hallazgo_id: f.id, campos: Object.keys(datos) }, despues: () => anotar(req, "hallazgo_modificar", "findings", f.id, Object.keys(datos).join(", ")) };
  }));

  router.delete("/engagements/:id/hallazgos/:fid", con("total"), escribir(async (req, tx) => {
    if (!["admin", "auditor"].includes(req.agente.rol)) throw new ErrorHttp(403, "Borrar hallazgos necesita que el dueño de la key sea admin o auditor, igual que en el panel.");
    const f = await tx.qRow("SELECT id, title FROM findings WHERE id=? AND engagement_id=?", [req.params.fid, req.engagement.id]);
    if (!f) throw new ErrorHttp(404, "El hallazgo no existe en este engagement.");
    await tx.qRun("DELETE FROM findings WHERE id=?", [f.id]);
    return { codigo: 200, cuerpo: { borrado: f.id }, despues: () => anotar(req, "hallazgo_borrar", "findings", f.id, f.title) };
  }));

  router.delete("/engagements/:id/logs/:lid", con("total"), escribir(async (req, tx) => {
    const l = await tx.qRow("SELECT id, fuera_de_alcance FROM operation_logs WHERE id=? AND engagement_id=?", [req.params.lid, req.engagement.id]);
    if (!l) throw new ErrorHttp(404, "El log no existe en este engagement.");
    if (l.fuera_de_alcance) throw new ErrorHttp(403, "Un log marcado como violación de alcance no se puede borrar.");
    await tx.qRun("DELETE FROM operation_logs WHERE id=?", [l.id]);
    return { codigo: 200, cuerpo: { borrado: l.id }, despues: () => anotar(req, "log_borrar", "operation_logs", l.id, "") };
  }));

  // ── Evidencias ──────────────────────────────────────────────────────────────
  async function guardarArchivo(req, tx, { hallazgoId = null, fase = null, descripcion = null }) {
    const nombre = path.basename(Buffer.from(req.file.originalname, "latin1").toString("utf8")).slice(0, 255);
    const tipo = TIPOS[path.extname(nombre).toLowerCase()];
    if (!tipo) throw new ErrorHttp(400, `Tipo de archivo no admitido. Se admiten: ${Object.keys(TIPOS).join(" ")}.`);
    const id = uuidv4(), archivo = crypto.randomBytes(16).toString("hex");
    await tx.qRun(
      "INSERT INTO evidences (id,engagement_id,finding_id,phase_type,filename,original_name,file_type,file_size,caption,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
      [id, req.engagement.id, hallazgoId, fase, archivo, nombre, tipo, req.file.size, descripcion, req.agente.userId]);
    // Se anota antes de escribir: si se corta a la mitad, también hay que borrarlo.
    req.archivosEscritos = [...(req.archivosEscritos || []), archivo];
    await fs.promises.writeFile(path.join(carpeta, archivo), req.file.buffer, { flag: "wx" });
    return { id, nombre };
  }

  router.post("/engagements/:id/evidencias", con("propuesta"), recibir, escribir(async (req, tx) => {
    if (!req.file) throw new ErrorHttp(400, `Falta el archivo (campo "archivo").`);
    const fase = opcion(req.body.fase, "fase", H.FASES);
    const descripcion = texto(req.body.descripcion, "descripcion", { max: 2000 });
    const hallazgoId = texto(req.body.hallazgo_id, "hallazgo_id", { max: 36 });
    if (hallazgoId && !(await tx.qRow("SELECT id FROM findings WHERE id=? AND engagement_id=?", [hallazgoId, req.engagement.id])))
      throw new ErrorHttp(404, "El hallazgo no existe en este engagement.");
    const ev = await guardarArchivo(req, tx, { hallazgoId, fase, descripcion });
    return { codigo: 201, cuerpo: { evidencia_id: ev.id, nombre: ev.nombre, bytes: req.file.size }, despues: () => anotar(req, "evidencia", "evidences", ev.id, ev.nombre) };
  }));

  router.delete("/engagements/:id/evidencias/:eid", con("total"), escribir(async (req, tx) => {
    const ev = await tx.qRow("SELECT id, filename, original_name FROM evidences WHERE id=? AND engagement_id=?", [req.params.eid, req.engagement.id]);
    if (!ev) throw new ErrorHttp(404, "La evidencia no existe en este engagement.");
    await tx.qRun("DELETE FROM evidences WHERE id=?", [ev.id]);
    return { codigo: 200, cuerpo: { borrado: ev.id }, despues: async () => {
      await sinFallar(`borrar el archivo de la evidencia ${ev.id}`, () => fs.promises.unlink(path.join(carpeta, path.basename(ev.filename))));
      await anotar(req, "evidencia_borrar", "evidences", ev.id, ev.original_name);
    } };
  }));

  // ── Importación de escaneos ─────────────────────────────────────────────────
  router.post("/engagements/:id/importar", con("propuesta"), recibir, escribir(async (req, tx) => {
    if (!req.file) throw new ErrorHttp(400, `Falta el archivo (campo "archivo").`);
    const formato = opcion(req.body.formato, "formato", importacion.FORMATOS, { obligatorio: true });
    const minima = opcion(req.body.severidad_minima, "severidad_minima", H.SEVERIDADES) || "info";
    const fase = opcion(req.body.fase, "fase", H.FASES) || "scanning";
    const leidos = importacion.leer(formato, req.file.buffer.toString("utf8"));
    await enFila(tx, req.engagement.id);
    const items = await alcanceDe(tx, req.engagement.id);
    const { aceptados, fuera, bajoMinimo, sinEquipo } = await importacion.clasificar(leidos, items, minima);
    const fueraDeAlcance = [...fuera].slice(0, TOPE_VIOLACIONES).map(([objetivo, motivo]) => ({ tipo: "importacion", objetivo, motivo }));
    if (fuera.size > TOPE_VIOLACIONES)
      fueraDeAlcance.push({ tipo: "importacion", objetivo: `${fuera.size - TOPE_VIOLACIONES} equipos más`, motivo: `El archivo trae ${fuera.size} equipos fuera de alcance.` });
    if (aceptados.length > importacion.TOPE) {
      const e = new ErrorHttp(413, `El archivo trae ${aceptados.length} hallazgos y el tope es ${importacion.TOPE}. Subí "severidad_minima" o dividí el archivo.`);
      e.violaciones = fueraDeAlcance;
      throw e;
    }

    // El original queda como evidencia: en la respuesta va solo el resumen.
    const ev = await guardarArchivo(req, tx, { fase, descripcion: `Escaneo importado (${formato})` });
    const directo = N.alcanza(req.engagement.nivel, "escritura");
    const creados = [];
    let duplicados = 0;
    for (const h of aceptados) {
      const datos = { ...h, phase_type: fase };
      if (await H.buscarDuplicado(tx, req.engagement.id, datos)) { duplicados++; continue; }
      const id = directo
        ? await H.insertar(tx, req.engagement.id, datos, req.agente.userId)
        : await H.proponer(tx, { engagementId: req.engagement.id, agente: req.agente, accion: "crear", datos });
      creados.push({ id, title: datos.title, severity: datos.severity, affected_asset: datos.affected_asset });
    }
    for (const v of fueraDeAlcance) await violacion(tx, req, v);
    const porSeveridad = Object.fromEntries(H.SEVERIDADES.map((s) => [s, creados.filter((c) => c.severity === s).length]).filter(([, n]) => n));
    return {
      codigo: 201,
      cuerpo: {
        evidencia_id: ev.id, leidos: leidos.length, [directo ? "hallazgos_creados" : "propuestas_creadas"]: creados.length,
        duplicados, bajo_severidad_minima: bajoMinimo, sin_equipo: sinEquipo, hosts_fuera_de_alcance: [...fuera.keys()].slice(0, 20), por_severidad: porSeveridad,
        muestra: req.ocultar.objeto(creados.slice(0, 15)), contenido_no_confiable: true,
        ...(fuera.size ? { alerta: `Se ignoraron resultados de ${fuera.size} host(s) fuera de alcance y quedó registrada la violación.` } : {}),
      },
      // Sin avisos por hallazgo, igual que la importación del panel: un escaneo mandaría cientos.
      despues: () => anotar(req, "importar", "findings", req.engagement.id, `${formato}: ${creados.length} de ${leidos.length}`),
    };
  }));

  // ── Metodología y técnicas ──────────────────────────────────────────────────
  router.put("/engagements/:id/metodologia/:item", con("escritura"), escribir(async (req, tx) => {
    const framework = opcion(req.body?.framework, "framework", Object.keys(CATALOGOS)) || "owasp_wstg";
    if (!CATALOGOS[framework].some((i) => i.key === req.params.item)) throw new ErrorHttp(400, `El ítem no pertenece a ${framework}.`);
    const estado = opcion(req.body?.estado, "estado", ["pending", "tested", "not_applicable"], { obligatorio: true });
    const nota = texto(req.body?.nota, "nota", { max: 1000 });
    H.exigirSinMarcas(nota);
    await tx.qRun(
      `INSERT INTO methodology_checks (id,engagement_id,framework,item_key,status,note,updated_by) VALUES (UUID(),?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE status=VALUES(status), note=COALESCE(VALUES(note), note), updated_by=VALUES(updated_by)`,
      [req.engagement.id, framework, req.params.item, estado, nota, req.agente.userId]); // Sin nota, queda la que había.
    return { codigo: 200, cuerpo: { framework, item: req.params.item, estado }, despues: () => anotar(req, "metodologia", "methodology_checks", null, `${req.params.item}: ${estado}`) };
  }));

  router.post("/engagements/:id/tecnicas", con("escritura"), escribir(async (req, tx) => {
    const b = req.body || {};
    H.exigirSinMarcas(b);
    const d = {
      mitre_id: texto(b.mitre_id, "mitre_id", { max: 20 }), name: texto(b.nombre, "nombre", { max: 200, obligatorio: true }),
      tactic: texto(b.tactica, "tactica", { max: 100 }), tool: texto(b.herramienta, "herramienta", { max: 200 }),
      notes: texto(b.notas, "notas", { max: 5000 }), phase_type: opcion(b.fase, "fase", H.FASES),
    };
    await enFila(tx, req.engagement.id);
    const ya = await tx.qRow("SELECT id FROM engagement_techniques WHERE engagement_id=? AND name=? AND mitre_id<=>? AND phase_type<=>?", [req.engagement.id, d.name, d.mitre_id, d.phase_type]);
    if (ya) throw new ErrorHttp(409, "Esa técnica ya está registrada en la fase.", { existente: ya.id });
    const id = uuidv4();
    await tx.qRun("INSERT INTO engagement_techniques (id,engagement_id,phase_type,mitre_id,name,tactic,tool,notes,added_by) VALUES (?,?,?,?,?,?,?,?,?)",
      [id, req.engagement.id, d.phase_type, d.mitre_id, d.name, d.tactic, d.tool, d.notes, req.agente.userId]);
    return { codigo: 201, cuerpo: { tecnica_id: id }, despues: () => anotar(req, "tecnica", "engagement_techniques", id, d.name) };
  }));
}

module.exports = { montar };
