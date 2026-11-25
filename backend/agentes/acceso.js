"use strict";
/**
 * Autenticación de agentes y acceso por engagement.
 *
 * Una key de agente solo vale en /api/agente/v1: el `auth()` del panel sigue aceptando únicamente
 * sesiones, así que ninguna ruta existente (usuarios, configuración, otras keys) se abre a un agente.
 */
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const N = require("./niveles");
const O = require("./ocultar");
const { ErrorHttp, ruta } = require("./comun");

const PREFIJO = "gnga_";
const FORMATO = /^gnga_[0-9a-f]{64}$/;

// La key tiene 256 bits al azar: un SHA-256 alcanza y deja buscarla por índice. bcrypt es para
// secretos que una persona elige.
const hashDeKey = (k) => crypto.createHash("sha256").update(k).digest("hex");
const nuevaKey = () => PREFIJO + crypto.randomBytes(32).toString("hex");

const enPausa = (que) => new ErrorHttp(423, `${que} Detené el trabajo, también en tu terminal, y avisá a la persona a cargo. No reintentes hasta que te lo pida.`, { pausado: true });

/** Todos los textos de un JSON con la forma que sea (los contactos de emergencia no tienen una fija). */
function textosDe(v) {
  if (typeof v === "string") {
    try { const j = JSON.parse(v); if (j && typeof j === "object") return textosDe(j); } catch { /* es texto */ }
    return [v];
  }
  return v && typeof v === "object" ? Object.values(v).flatMap(textosDe) : [];
}

/** Lo que identifica al cliente, en una fila con los campos de CAMPOS_CLIENTE. */
const CAMPOS_CLIENTE = "c.name AS cliente, c.contact_name, c.contact_phone, c.exec_contact_name, e.emergency_contacts";
const nombresDe = (e) => [e.cliente, e.contact_name, e.contact_phone, e.exec_contact_name, ...textosDe(e.emergency_contacts)];

function crear({ qRow, qRun, secretoBase, limitePorVentana = 3000 }) {
  // Intentos fallidos por IP. Solo se aplica al rechazar: una key válida nunca queda bloqueada por las
  // inválidas que otro mande desde la misma dirección.
  const limiteFallidos = rateLimit({
    windowMs: 15 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false,
    message: { error: "Demasiados intentos con una key inválida. Reintentá en 15 minutos." },
  });
  // Keys que entraron en este proceso, por su hash. No autorizan nada: solo eximen del techo por dirección.
  const conocidas = new Set();
  const keyDe = (req) => {
    const h = req.headers.authorization;
    return typeof h === "string" && h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  };
  // Techo por dirección, antes de mirar la key: acota lo que cuesta rechazar pedidos sin autenticar. No cuenta
  // ni frena a una key que ya entró: esa tiene su propio límite.
  const limitePorIp = rateLimit({
    windowMs: 15 * 60 * 1000, max: limitePorVentana * 4, standardHeaders: true, legacyHeaders: false,
    skip: (req) => { const k = keyDe(req); return FORMATO.test(k) && conocidas.has(hashDeKey(k)); },
    message: { error: "Demasiados pedidos desde esta dirección. Reintentá en unos minutos." },
  });
  // Límite propio por key: un agente no agota el cupo del panel ni el de otra key.
  const limitePorKey = rateLimit({
    windowMs: 15 * 60 * 1000, max: limitePorVentana, standardHeaders: true, legacyHeaders: false,
    keyGenerator: (req) => req.agente.keyId,
    message: { error: "La key superó su límite de pedidos. Reintentá en unos minutos." },
  });

  const rechazar = (req, res, mensaje) => limiteFallidos(req, res, () => res.status(401).json({ error: mensaje }));

  const autenticar = ruta(async (req, res, next) => {
    const key = keyDe(req);
    if (!FORMATO.test(key)) return rechazar(req, res, "Falta una key de agente válida (Authorization: Bearer gnga_...).");
    const hash = hashDeKey(key);
    const k = await qRow(
      `SELECT k.id, k.nombre, k.nivel_max, k.revocada_en IS NOT NULL AS revocada, k.expira_en <= NOW() AS vencida,
              (k.ultimo_uso IS NULL OR k.ultimo_uso < NOW() - INTERVAL 1 MINUTE) AS anotar_uso,
              u.id AS user_id, u.username, u.role, u.is_active, u.must_change_password,
              (SELECT p.pausado_en IS NOT NULL FROM agente_pausa p WHERE p.id=1) AS pausado
       FROM agente_keys k JOIN users u ON u.id=k.user_id WHERE k.hash=?`, [hash]);
    if (!k || !k.is_active || k.revocada || k.vencida || k.must_change_password) conocidas.delete(hash);
    if (!k || !k.is_active) return rechazar(req, res, "La key no es válida.");
    if (k.revocada) return rechazar(req, res, "La key fue revocada.");
    if (k.vencida) return rechazar(req, res, "La key está vencida.");
    if (k.must_change_password) throw new ErrorHttp(403, "El usuario dueño de la key tiene que cambiar su contraseña inicial.");
    req.agente = {
      keyId: k.id, keyNombre: k.nombre, userId: k.user_id, username: k.username, rol: k.role,
      nivelMax: N.efectivo(k.nivel_max, N.techoDeRol(k.role)), pausado: Boolean(k.pausado),
    };
    conocidas.add(hash);
    // Es un dato informativo: que falle o espere un bloqueo no puede frenar el pedido.
    if (k.anotar_uso) qRun("UPDATE agente_keys SET ultimo_uso=NOW() WHERE id=?", [k.id]).catch(() => {});
    next();
  });

  /** Corta todo si los agentes están en pausa. Va después del límite por key: insistir gasta su cupo. */
  const sinPausa = ruta(async (req, res, next) => {
    if (req.agente.pausado) throw enPausa("Agentes en pausa: lo decidió una persona.");
    next();
  });
  /**
   * Vuelve a mirar la pausa justo antes de confirmar una escritura. El bloqueo compartido hace que pausar
   * espere a lo que ya está por confirmarse: cuando el panel dice que está en pausa, nada más se guarda.
   */
  async function exigirSinPausa(tx, engagementId) {
    const g = await tx.qRow("SELECT pausado_en FROM agente_pausa WHERE id=1 LOCK IN SHARE MODE");
    if (g?.pausado_en) throw enPausa("Agentes en pausa: lo decidió una persona. Esto no se guardó.");
    const e = await tx.qRow("SELECT pausado_en FROM agente_engagements WHERE engagement_id=? LOCK IN SHARE MODE", [engagementId]);
    if (e?.pausado_en) throw enPausa("Engagement en pausa: lo decidió una persona. Esto no se guardó.");
  }

  /**
   * Carga el engagement de `:id` si la key y el engagement lo permiten y exige un nivel mínimo.
   * Si no hay acceso responde lo mismo que si no existiera.
   */
  const conEngagement = (minimo) => ruta(async (req, res, next) => {
    const e = await qRow(
      `SELECT e.id, e.title, e.status, ae.nivel_max, ae.mostrar_sensibles, ae.pausado_en,
              ${CAMPOS_CLIENTE}
       FROM engagements e
       JOIN agente_key_engagements ke ON ke.engagement_id=e.id AND ke.key_id=?
       JOIN agente_engagements ae ON ae.engagement_id=e.id
       JOIN clients c ON c.id=e.client_id
       WHERE e.id=?`, [req.agente.keyId, req.params.id]);
    const nivel = e ? N.efectivo(req.agente.nivelMax, e.nivel_max, N.techoDeEstado(e.status)) : "ninguno";
    if (nivel === "ninguno") throw new ErrorHttp(404, "El engagement no existe o la key no tiene acceso.");
    if (e.pausado_en) throw enPausa("Engagement en pausa: lo decidió una persona.");
    if (!N.alcanza(nivel, minimo))
      throw new ErrorHttp(403, `Esta acción necesita el nivel "${minimo}" y acá el nivel efectivo es "${nivel}". Lo cambia una persona desde el panel.`, { nivel_requerido: minimo, nivel_efectivo: nivel });
    req.engagement = { id: e.id, titulo: e.title, nivel };
    req.ocultar = O.crear({
      activo: !e.mostrar_sensibles, secreto: secretoBase, engagementId: e.id,
      nombres: nombresDe(e),
    });
    next();
  });

  const ocultador = (opciones) => O.crear({ secreto: secretoBase, ...opciones });

  return { limitePorIp, limitePorKey, autenticar, sinPausa, exigirSinPausa, conEngagement, ocultador };
}

module.exports = { crear, nuevaKey, hashDeKey, CAMPOS_CLIENTE, nombresDe };
