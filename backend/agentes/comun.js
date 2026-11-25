"use strict";
/** Utilidades de las rutas de agentes: errores de entrada, validación de campos y recortes. */

/** Error con respuesta HTTP propia. Cualquier otro llega al manejador general como 500. */
class ErrorHttp extends Error {
  constructor(codigo, mensaje, extra = {}) {
    super(mensaje);
    this.codigo = codigo;
    this.extra = extra;
  }
}

/** Envuelve un handler para que los ErrorHttp salgan con su código y su mensaje. */
const ruta = (fn) => async (req, res, next) => {
  try { await fn(req, res, next); } catch (e) {
    if (!(e instanceof ErrorHttp)) return next(e);
    res.status(e.codigo).json({ error: e.message, ...e.extra });
  }
};

/** Texto validado. Un valor que no es texto se rechaza: mysql2 trata distinto objetos y listas. */
function texto(v, campo, { max = 1000, obligatorio = false } = {}) {
  if (v === undefined || v === null || v === "") {
    if (obligatorio) throw new ErrorHttp(400, `"${campo}" es obligatorio.`);
    return null;
  }
  if (typeof v !== "string") throw new ErrorHttp(400, `"${campo}" tiene que ser texto.`);
  const s = v.trim();
  if (!s && obligatorio) throw new ErrorHttp(400, `"${campo}" es obligatorio.`);
  if (s.length > max) throw new ErrorHttp(400, `"${campo}" supera los ${max} caracteres.`);
  return s || null;
}

function opcion(v, campo, opciones, { obligatorio = false } = {}) {
  const s = texto(v, campo, { max: 100, obligatorio });
  if (s !== null && !opciones.includes(s)) throw new ErrorHttp(400, `"${campo}" tiene que ser uno de: ${opciones.join(", ")}.`);
  return s;
}

function entero(v, campo, { min, max, porDefecto }) {
  if (v === undefined || v === null || v === "") return porDefecto;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new ErrorHttp(400, `"${campo}" tiene que ser un entero entre ${min} y ${max}.`);
  return n;
}

const MARCA_RECORTE = "[RECORTADO:";
function recortar(s, max) {
  if (typeof s !== "string" || s.length <= max) return s;
  return `${s.slice(0, max)}\n${MARCA_RECORTE} faltan ${s.length - max} caracteres]`;
}
function tieneRecorte(v) {
  if (typeof v === "string") return v.includes(MARCA_RECORTE);
  if (v && typeof v === "object") return Object.values(v).some(tieneRecorte);
  return false;
}

module.exports = { ErrorHttp, ruta, texto, opcion, entero, recortar, tieneRecorte };
