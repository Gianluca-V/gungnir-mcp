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
  const notificar = async (id, titulo) => {
    const f = await qRow("SELECT * FROM findings WHERE id=?", [id]);
    avisar(f, { name: escaparHtml(titulo) }).catch(() => {});
  };

  const router = express.Router();
  router.use(acceso.autenticar, acceso.limitePorKey);
  lectura.montar(router, { ...deps, acceso, buscarCve: cve.crear() });
  escritura.montar(router, { ...deps, acceso, notificar });
  router.use((req, res) => res.status(404).json({ error: "Ruta inexistente." }));
  app.use(BASE, router);

  panel.montar(app, { ...deps, notificarHallazgo: (f, e) => avisar(f, e && { name: escaparHtml(e.name) }) });
}

module.exports = { montar, crearTablas, esPedidoDeAgente };
