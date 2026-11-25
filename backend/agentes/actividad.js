"use strict";
/**
 * Actividad de cada key: lo que escribió y lo que se le rechazó, para verlo junto en el panel.
 *
 * Las lecturas no se anotan. Lo rechazado que se repite seguido se agrupa, para que un agente en un bucle
 * no llene la tabla. Es un registro de apoyo: si falla, el pedido sigue igual y la auditoría general queda.
 */
const DIAS = 90;
const AGRUPAR_MS = 10 * 60 * 1000;
const DIA_MS = 24 * 60 * 60 * 1000;

const ACCIONES = [
  ["POST", /^\/engagements\/[^/]+\/alcance\/verificar\/?$/, "consulta"],
  ["POST", /^\/engagements\/[^/]+\/logs\/?$/, "log"],
  ["DELETE", /^\/engagements\/[^/]+\/logs\//, "log_borrar"],
  ["POST", /^\/engagements\/[^/]+\/hallazgos\/?$/, "hallazgo_crear"],
  ["PUT", /^\/engagements\/[^/]+\/hallazgos\//, "hallazgo_modificar"],
  ["DELETE", /^\/engagements\/[^/]+\/hallazgos\//, "hallazgo_borrar"],
  ["POST", /^\/engagements\/[^/]+\/evidencias\/?$/, "evidencia"],
  ["DELETE", /^\/engagements\/[^/]+\/evidencias\//, "evidencia_borrar"],
  ["POST", /^\/engagements\/[^/]+\/importar\/?$/, "importar"],
  ["PUT", /^\/engagements\/[^/]+\/metodologia\//, "metodologia"],
  ["POST", /^\/engagements\/[^/]+\/tecnicas\/?$/, "tecnica"],
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

function crear({ qRun }) {
  const ultimas = new Map(); // Por key: la última fila, para agrupar. Y la cola, para no cruzar dos anotaciones.
  const colas = new Map();
  let limpieza = 0;

  async function anotar(f) {
    const firma = JSON.stringify([f.accion, f.codigo, f.engagementId, f.objetivo, f.detalle, f.fuera]);
    const u = ultimas.get(f.keyId);
    if (f.codigo >= 400 && u?.firma === firma && Date.now() - u.desde < AGRUPAR_MS) {
      await qRun("UPDATE agente_actividad SET veces=veces+1, ultima_en=NOW() WHERE id=?", [u.id]);
      return;
    }
    const [r] = await qRun(
      "INSERT INTO agente_actividad (key_id,engagement_id,accion,codigo,objetivo,detalle,fuera) VALUES (?,?,?,?,?,?,?)",
      [f.keyId, f.engagementId, f.accion, f.codigo, f.objetivo, f.detalle, f.fuera ? 1 : 0]);
    ultimas.set(f.keyId, { firma, id: r.insertId, desde: Date.now() });
    if (Date.now() - limpieza > DIA_MS) {
      limpieza = Date.now();
      await qRun(`DELETE FROM agente_actividad WHERE ultima_en < NOW() - INTERVAL ${DIAS} DAY LIMIT 20000`);
    }
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
        const f = {
          keyId, engagementId: req.engagementId || null, accion, codigo, objetivo: objetivoDe(req, ruta),
          detalle: codigo >= 400 ? corto(req.motivoRechazo || cuerpo?.error) : corto(req.body?.comando), fuera: Boolean(req.violaciones?.length),
        };
        const cola = (colas.get(keyId) || Promise.resolve()).then(() => anotar(f))
          .catch((e) => console.error("[GUNGNIR] Agentes: no se pudo anotar la actividad:", e?.message));
        colas.set(keyId, cola);
      }
      return enviar(cuerpo);
    };
    next();
  };
  return { registrar };
}

module.exports = { crear, accionDe, DIAS };
