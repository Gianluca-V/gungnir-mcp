"use strict";
/** Retest propuesto por un agente. Siempre lo aprueba una persona: cierra o reabre un hallazgo. */
const R = require("../retest");
const H = require("./hallazgos");
const { ErrorHttp, texto, opcion } = require("./comun");

const CAMPOS = ["resultado", "objetivo", "retest_severity", "notas"];

/** Valida lo que llega. Sin `objetivo` vale el activo del hallazgo. */
function validar(b, activo = null) {
  if (!b || typeof b !== "object" || Array.isArray(b)) throw new ErrorHttp(400, "Falta el cuerpo del retest.");
  const sobran = Object.keys(b).filter((k) => !CAMPOS.includes(k));
  if (sobran.length) throw new ErrorHttp(400, `Campos no admitidos: ${sobran.join(", ")}. Se admiten: ${CAMPOS.join(", ")}.`);
  const d = {
    resultado: opcion(b.resultado, "resultado", R.RESULTADOS, { obligatorio: true }),
    objetivo: texto(b.objetivo, "objetivo", { max: 500 }) ?? activo,
    notas: texto(b.notas, "notas", { max: 20000, obligatorio: true }),
  };
  const severidad = opcion(b.retest_severity, "retest_severity", H.SEVERIDADES);
  if (severidad && d.resultado === "passed") throw new ErrorHttp(400, `Con "passed" la severidad queda en info: no envíes "retest_severity".`);
  if (severidad) d.retest_severity = severidad;
  if (!d.objetivo) throw new ErrorHttp(400, `Indicá en "objetivo" qué se probó: el hallazgo no tiene un activo.`);
  H.exigirSinMarcas(d);
  return d;
}

const aceptado = () => new ErrorHttp(409, "Una persona aceptó el riesgo de este hallazgo: no se reprueba desde acá.");

module.exports = { validar, aceptado };
