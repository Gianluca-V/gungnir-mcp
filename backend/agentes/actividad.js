"use strict";
/**
 * Actividad de cada key: lo que escribió y lo que se le rechazó, para verlo junto en el panel.
 *
 * Las lecturas no se anotan. Lo rechazado que se repite seguido se agrupa, y hay un tope de rechazos
 * distintos por ventana, para que un agente en un bucle no llene la tabla. El comando no se copia: se lee
 * del log, así se va con él. Es un registro de apoyo: si falla, el pedido sigue igual y la auditoría general queda.
 */
const DIAS = 90;
const AGRUPAR_MS = 10 * 60 * 1000;
const RECHAZOS_POR_VENTANA = 200;
const TANDA = 5000;
const DIA_MS = 24 * 60 * 60 * 1000;

const ACCIONES = [
  ["POST", /^\/engagements\/[^/]+\/alcance\/verificar\/?$/i, "consulta"],
  ["POST", /^\/engagements\/[^/]+\/logs\/?$/i, "log"],
  ["DELETE", /^\/engagements\/[^/]+\/logs\//i, "log_borrar"],
  ["POST", /^\/engagements\/[^/]+\/hallazgos\/?$/i, "hallazgo_crear"],
  ["PUT", /^\/engagements\/[^/]+\/hallazgos\//i, "hallazgo_modificar"],
  ["DELETE", /^\/engagements\/[^/]+\/hallazgos\//i, "hallazgo_borrar"],
  ["POST", /^\/engagements\/[^/]+\/evidencias\/?$/i, "evidencia"],
  ["DELETE", /^\/engagements\/[^/]+\/evidencias\//i, "evidencia_borrar"],
  ["POST", /^\/engagements\/[^/]+\/importar\/?$/i, "importar"],
  ["PUT", /^\/engagements\/[^/]+\/metodologia\//i, "metodologia"],
  ["POST", /^\/engagements\/[^/]+\/tecnicas\/?$/i, "tecnica"],
];
function accionDe(metodo, ruta) {
  if (metodo === "GET" || metodo === "HEAD") return "consulta";
  return ACCIONES.find(([m, re]) => m === metodo && re.test(ruta))?.[2] || "otra";
}

const corto = (v, n = 500) => (typeof v === "string" && v.trim() ? v.trim().slice(0, n) : null);

/** Sobre qué fue el pedido. El cuerpo lo manda el agente: puede traer cualquier cosa. */
function objetivoDe(req, ruta) {
  const b = req.body && typeof req.body === "object" ? req.body : {};
  const partes = [corto(b.title, 300), corto(b.affected_asset), corto(b.objetivo), corto(b.nombre, 200), req.file && corto(Buffer.from(req.file.originalname, "latin1").toString("utf8"), 255)].filter(Boolean);
  if (!partes.length) partes.push(corto(/\/(?:metodologia|hallazgos|logs|evidencias)\/([\w-]{1,80})/.exec(ruta)?.[1]));
  return corto(partes.filter(Boolean).join(" · "));
}

/** Borra lo que pasó su plazo, de a tandas para no retener bloqueos. */
async function limpiar(qRun) {
  for (;;) {
    const [r] = await qRun(`DELETE FROM agente_actividad WHERE ultima_en < NOW() - INTERVAL ${DIAS} DAY LIMIT ${TANDA}`);
    if (r.affectedRows < TANDA) return;
  }
}

function crear({ qRun }) {
  const fallo = (e) => console.error("[GUNGNIR] Agentes: no se pudo anotar la actividad:", e?.message);
  const ultimas = new Map(); // Por key: la última fila, para agrupar, y cuántos rechazos van en la ventana.
  const colas = new Map(); // Por key: lo pendiente, para no cruzar dos anotaciones.
  setInterval(() => limpiar(qRun).catch(fallo), DIA_MS).unref();
  let limpieza = false;

  async function anotar(f) {
    const ahora = Date.now(), rechazo = f.codigo >= 400;
    let u = ultimas.get(f.keyId);
    if (!u || ahora - u.desde > AGRUPAR_MS) u = { desde: ahora, rechazos: 0, firma: null, id: null, resto: null };
    ultimas.set(f.keyId, u);
    const repetir = (id) => qRun("UPDATE agente_actividad SET veces=veces+1, ultima_en=NOW() WHERE id=?", [id]);
    const firma = JSON.stringify([f.accion, f.codigo, f.engagementId, f.objetivo, f.detalle, f.fuera]);
    if (rechazo && u.firma === firma) return repetir(u.id);
    const deMas = rechazo && u.rechazos >= RECHAZOS_POR_VENTANA;
    if (deMas && u.resto) return repetir(u.resto);
    if (deMas) Object.assign(f, { accion: "otra", engagementId: null, objetivo: null, detalle: "Más rechazos distintos en pocos minutos, sin detallar.", fuera: false });
    const [r] = await qRun(
      "INSERT INTO agente_actividad (key_id,engagement_id,accion,codigo,objetivo,detalle,ref_id,fuera) VALUES (?,?,?,?,?,?,?,?)",
      [f.keyId, f.engagementId, f.accion, f.codigo, f.objetivo, f.detalle, f.refId, f.fuera ? 1 : 0]);
    if (deMas) u.resto = r.insertId;
    else Object.assign(u, { firma, id: r.insertId, rechazos: u.rechazos + (rechazo ? 1 : 0) });
    if (!limpieza) { limpieza = true; await limpiar(qRun); } // Con la primera anotación del proceso; después, una vez por día.
  }

  /** Anota al responder, y no al terminar de enviar: si el cliente cortó, la escritura se hizo igual. */
  const registrar = (req, res, next) => {
    const ruta = req.path, accion = accionDe(req.method, ruta), enviar = res.json.bind(res);
    res.json = (cuerpo) => {
      const keyId = req.agente?.keyId || req.keyRechazada;
      // Con una key que existe y ya no vale, importa por qué se rechazó y no que además superó el límite.
      const codigo = req.motivoRechazo ? 401 : res.statusCode;
      const interesa = codigo >= 400 ? codigo !== 429 && !cuerpo?.en_curso : accion !== "consulta" && !res.get("Idempotency-Replayed");
      if (keyId && interesa) {
        // Sin autenticar no importa qué pidió: solo que esa key se quiso usar. Así se agrupa siempre.
        const f = req.motivoRechazo
          ? { keyId, engagementId: null, accion: "acceso", codigo, objetivo: null, detalle: req.motivoRechazo, refId: null, fuera: false }
          : {
            keyId, engagementId: req.engagementId || null, accion, codigo, objetivo: objetivoDe(req, ruta),
            detalle: codigo >= 400 ? corto(cuerpo?.error) : null, refId: accion === "log" && codigo < 400 ? corto(cuerpo?.id, 36) : null,
            fuera: Boolean(req.violaciones?.length),
          };
        const cola = (colas.get(keyId) || Promise.resolve()).then(() => anotar(f))
          .catch(fallo);
        colas.set(keyId, cola);
      }
      return enviar(cuerpo);
    };
    next();
  };
  return { registrar };
}

module.exports = { crear, limpiar, accionDe, DIAS };
