"use strict";
/**
 * Secciones del engagement que un agente escribe además de hallazgos: tiempo, fase activa, fases del
 * modo custom y el resumen del informe. Acá se valida lo que llega; las rutas y la aprobación lo usan igual.
 */
const crypto = require("crypto");
const H = require("./hallazgos");
const { FASES } = require("../fases");
const { ErrorHttp, texto, opcion } = require("./comun");

const ESTADOS_FASE = ["not_started", "in_progress", "completed"];
const MAX_MINUTOS = 24 * 60;
// TEXT guarda 65.535 bytes: con cuatro bytes por carácter, 15.000 entran siempre.
const MAX_TEXTO = 15000;

function exigirCampos(b, campos, que) {
  if (!b || typeof b !== "object" || Array.isArray(b)) throw new ErrorHttp(400, `Falta el cuerpo ${que}.`);
  const sobran = Object.keys(b).filter((k) => !campos.includes(k));
  if (sobran.length) throw new ErrorHttp(400, `Campos no admitidos: ${sobran.join(", ")}. Se admiten: ${campos.join(", ")}.`);
}

/** El día de hoy en la hora del panel (UTC-3), como lo carga la pantalla de tiempo. */
const hoy = () => new Date(Date.now() - 3 * 3600 * 1000).toISOString().slice(0, 10);

function fecha(v) {
  const s = texto(v, "fecha", { max: 10 });
  if (s === null) return hoy();
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  const d = m && new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  if (!d || d.getUTCMonth() !== +m[2] - 1 || +m[1] < 2000) throw new ErrorHttp(400, `"fecha" tiene que ser un día válido, como 2026-11-20.`);
  if (s > hoy()) throw new ErrorHttp(400, `"fecha" no puede ser futura: se carga el tiempo ya trabajado.`);
  return s;
}

/** Tiempo trabajado. Va en una fase estándar o en una fase custom, nunca en las dos. */
function validarTiempo(b) {
  exigirCampos(b, ["minutos", "fase", "fase_custom", "nota", "fecha"], "del tiempo");
  if (!Number.isInteger(b.minutos) || b.minutos < 1 || b.minutos > MAX_MINUTOS)
    throw new ErrorHttp(400, `"minutos" tiene que ser un entero entre 1 y ${MAX_MINUTOS}.`);
  const d = {
    minutos: b.minutos, fase: opcion(b.fase, "fase", FASES), fase_custom: texto(b.fase_custom, "fase_custom", { max: 36 }),
    nota: texto(b.nota, "nota", { max: 500 }), fecha: fecha(b.fecha),
  };
  if (d.fase && d.fase_custom) throw new ErrorHttp(400, `Indicá una sola: "fase" o "fase_custom".`);
  H.exigirSinMarcas(d);
  return d;
}

function validarFase(b) {
  exigirCampos(b, ["fase"], "del cambio de fase");
  return { fase: opcion(b.fase, "fase", FASES, { obligatorio: true }) };
}

module.exports = { FASES, ESTADOS_FASE, MAX_TEXTO, validarTiempo, validarFase, huellaDeTexto: (...v) => crypto.createHash("sha256").update(JSON.stringify(v)).digest("hex") };
