"use strict";
/**
 * Agentes: acceso de herramientas como opencode o Claude Code a un engagement, por medio del
 * servidor MCP de `mcp/`.
 *
 *   /api/agente/v1   para el agente, con su key. Es lo único que una key puede tocar.
 *   /api/agentes     para el panel, con sesión: keys, niveles, propuestas y violaciones.
 */
const express = require("express");
const accesoAgente = require("./acceso");
const { crearTablas } = require("./esquema");
const panel = require("./panel");
const lectura = require("./lectura");
const escritura = require("./escritura");
const cve = require("./cve");
const actividad = require("./actividad");

const BASE = "/api/agente/v1";
const escaparHtml = (s) => (s == null ? s : String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`));

/** Los pedidos del agente tienen su propio límite y no gastan el del panel. */
const esPedidoDeAgente = (req) => req.originalUrl.startsWith(`${BASE}/`);

function montar(app, deps) {
  const { qRow, qRun, notificarHallazgo, secretoBase } = deps;
  const limite = Number(process.env.AGENTE_LIMITE_15MIN) || 3000;
  const acceso = accesoAgente.crear({ qRow, qRun, secretoBase, limitePorVentana: limite });

  // El correo arma su cuerpo en HTML: lo que escribió un agente entra escapado.
  const avisar = (f, e) => notificarHallazgo(f && { ...f, title: escaparHtml(f.title), affected_asset: escaparHtml(f.affected_asset) }, e);
  /** Aviso de un hallazgo nuevo. Nunca lanza ni espera al correo: el hallazgo ya está guardado. */
  const avisarSeguro = async (id, buscar) => {
    const fallo = (e) => console.error(`[GUNGNIR] Agentes: no se pudo avisar el hallazgo ${id}:`, e?.message);
    try { avisar(await qRow("SELECT * FROM findings WHERE id=?", [id]), await buscar()).catch(fallo); } catch (e) { fallo(e); }
  };
  const notificar = (id, titulo) => avisarSeguro(id, () => ({ name: escaparHtml(titulo) }));

  const router = express.Router();
  const entrada = [acceso.limitePorIp, actividad.crear({ qRun }).registrar, acceso.autenticar, acceso.limitePorKey, acceso.sinPausa];
  router.use(...entrada);
  lectura.montar(router, { ...deps, acceso, buscarCve: cve.crear(), explotacion: cve.crearExplotacion({ qRow }) });
  escritura.montar(router, { ...deps, acceso, notificar });
  router.use((req, res) => res.status(404).json({ error: "Ruta inexistente." }));
  app.use(BASE, router);

  // Un cuerpo ilegible falla antes de llegar al router: igual se autentica, gasta cupo y queda en la actividad.
  const ilegible = express.Router();
  ilegible.use(...entrada);
  ilegible.use((req, res) => res.status(req.errorDeCuerpo.codigo).json({ error: req.errorDeCuerpo.mensaje }));
  app.use(BASE, (err, req, res, next) => {
    const deCuerpo = /^(entity|encoding|charset|request)\./.test(err?.type || "") || /^Z_/.test(err?.code || "");
    if (!deCuerpo && !(err instanceof URIError)) return next(err);
    const codigo = deCuerpo && err.status >= 400 && err.status < 500 ? err.status : 400;
    const mensaje = !deCuerpo ? "La dirección del pedido no se puede leer."
      : codigo === 413 ? "El pedido supera los 2 MB. Subí lo grande como evidencia."
        : err.type === "entity.parse.failed" ? "JSON inválido en el cuerpo del pedido." : "El cuerpo del pedido no se puede leer.";
    if (req.agente) return res.status(codigo).json({ error: mensaje }); // Ya pasó por la entrada.
    req.errorDeCuerpo = { codigo, mensaje };
    ilegible(req, res, next);
  });

  panel.montar(app, { ...deps, notificar: (id, engagementId) => avisarSeguro(id, async () => {
    const e = await qRow("SELECT title FROM engagements WHERE id=?", [engagementId]);
    return { name: escaparHtml(e?.title) };
  }) });
}

module.exports = { montar, crearTablas, esPedidoDeAgente };
