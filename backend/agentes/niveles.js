"use strict";
/**
 * Niveles de autonomía de un agente. Van de menor a mayor y cada uno incluye a los anteriores:
 *
 *   ninguno    sin acceso (el valor por defecto de todo engagement).
 *   lectura    consulta.
 *   propuesta  registra logs y evidencias; los hallazgos quedan a aprobar por una persona.
 *   escritura  crea y modifica; no borra.
 *   total      además borra dentro de su engagement.
 *
 * El nivel que vale es el más restrictivo de todos los topes (key, engagement, rol del dueño de la
 * key y estado del engagement). Un valor que falta o que no se reconoce cuenta como "ninguno".
 */
const NIVELES = ["ninguno", "lectura", "propuesta", "escritura", "total"];
const NIVELES_DE_KEY = NIVELES.slice(1);

const orden = (n) => Math.max(0, NIVELES.indexOf(n));
const efectivo = (...topes) => NIVELES[Math.min(...topes.map(orden))];

function alcanza(nivel, minimo) {
  return NIVELES_DE_KEY.includes(minimo) && orden(nivel) >= orden(minimo);
}

function techoDeRol(rol) {
  if (rol === "lector") return "lectura";
  return ["admin", "auditor", "pentester"].includes(rol) ? "total" : "ninguno";
}

/** Lo entregado o archivado ya salió en un informe: se consulta, no se modifica. */
function techoDeEstado(estado) {
  return estado === "delivered" || estado === "archived" ? "lectura" : "total";
}

module.exports = { NIVELES, NIVELES_DE_KEY, efectivo, alcanza, techoDeRol, techoDeEstado };
