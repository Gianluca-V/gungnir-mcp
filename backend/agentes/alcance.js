"use strict";
/**
 * Decide si un objetivo está dentro del alcance de un engagement.
 *
 * Reglas:
 *  - Sin ítems dentro de alcance, todo queda fuera.
 *  - Una exclusión gana siempre. Un rango que toca una exclusión queda fuera entero.
 *  - Un dominio vale solo para sí mismo; los subdominios se piden con "*.dominio".
 *  - Una URL acota esquema, puerto y prefijo de ruta (por segmento completo).
 *  - Lo que no se puede interpretar queda fuera. Si lo ilegible es una exclusión de red, nada queda
 *    dentro: no se puede saber qué excluye.
 *
 * No resuelve DNS: compara lo que se declara con lo que está cargado. Es un control de registro, no
 * un cortafuegos.
 */

const MAX32 = (1n << 32n) - 1n;
const HOST = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62})(?:\.[a-z0-9_][a-z0-9_-]{0,62})*$/;
const PUERTO_DE_ESQUEMA = { http: 80, https: 443, ftp: 21, ws: 80, wss: 443 };

function ipv4ANumero(s) {
  const p = s.split(".");
  if (p.length !== 4 || !p.every((x) => /^(0|[1-9]\d{0,2})$/.test(x) && Number(x) <= 255)) return null;
  return p.reduce((n, x) => (n << 8n) | BigInt(x), 0n);
}

/** `s` sale de URL, así que ya está en forma canónica (minúsculas, sin parte IPv4). */
function ipv6ANumero(s) {
  const mitades = s.split("::");
  if (mitades.length > 2) return null;
  const a = mitades[0] ? mitades[0].split(":") : [];
  const b = mitades.length === 2 && mitades[1] ? mitades[1].split(":") : [];
  const faltan = 8 - a.length - b.length;
  if (mitades.length === 1 ? faltan !== 0 : faltan < 0) return null;
  const grupos = [...a, ...Array(mitades.length === 2 ? faltan : 0).fill("0"), ...b];
  if (!grupos.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return grupos.reduce((n, g) => (n << 16n) | BigInt(`0x${g}`), 0n);
}

/** Host en forma canónica: { ip: {v, n} } o { host }. Null si no es un host válido. */
function canonizarHost(crudo) {
  let h = String(crudo).trim().toLowerCase().replace(/\.$/, "");
  if (!h) return null;
  // 010.1.1.1 es 8.1.1.1 para unas herramientas y 10.1.1.1 para otras: no se adivina.
  if (/^[\d.]+$/.test(h) && h.split(".").some((x) => /^0\d/.test(x))) return null;
  if (h.includes(":") && !h.startsWith("[")) h = `[${h}]`;
  let canon;
  try { canon = new URL(`http://${h}/`).hostname; } catch { return null; }
  if (canon.startsWith("[")) {
    const n = ipv6ANumero(canon.slice(1, -1));
    if (n === null) return null;
    return (n >> 32n) === 0xffffn ? { ip: { v: 4, n: n & MAX32 } } : { ip: { v: 6, n } };
  }
  const n4 = ipv4ANumero(canon);
  if (n4 !== null) return { ip: { v: 4, n: n4 } };
  return HOST.test(canon) ? { host: canon } : null;
}

function rangoCidr(s) {
  const m = /^([^/]+)\/(\d{1,3})$/.exec(s);
  if (!m) return null;
  const c = canonizarHost(m[1].replace(/^\[|\]$/g, ""));
  if (!c?.ip) return null;
  const bits = c.ip.v === 4 ? 32 : 128;
  const largo = Number(m[2]);
  if (largo > bits) return { ilegible: true };
  const libres = BigInt(bits - largo);
  const ini = (c.ip.n >> libres) << libres;
  return { clase: "ip", v: c.ip.v, ini, fin: ini | ((1n << libres) - 1n), puerto: null };
}

/** 10.0.0.1-20 (la forma de rangos de nmap en el último octeto) y 10.0.0.1-10.0.0.20. */
function rangoConGuion(s) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:(?:\.\d{1,3}){3})?)$/.exec(s);
  if (!m) return null;
  const ini = ipv4ANumero(m[1]);
  const fin = ipv4ANumero(m[2].includes(".") ? m[2] : m[1].replace(/\d+$/, m[2]));
  if (ini === null || fin === null || fin < ini) return { ilegible: true };
  return { clase: "ip", v: 4, ini, fin, puerto: null };
}

function conHost(c, resto) {
  return c.ip ? { v: c.ip.v, ini: c.ip.n, fin: c.ip.n, ...resto } : { host: c.host, ...resto };
}

function leerUrl(s, conEsquema) {
  let u;
  try { u = new URL(conEsquema ? s : `http://${s}`); } catch { return null; }
  const c = canonizarHost(u.hostname.replace(/^\[|\]$/g, ""));
  if (!c) return null;
  let ruta;
  try { ruta = decodeURIComponent(u.pathname); } catch { return null; }
  // Tras decodificar no puede quedar nada que suba de directorio: cada servidor lo lee distinto.
  if (ruta.includes("\\") || ruta.split("/").some((p) => p === ".." || p === ".") || /%2e|%2f|%5c/i.test(ruta)) return null;
  const esquema = conEsquema ? u.protocol.slice(0, -1) : null;
  const puerto = u.port ? Number(u.port) : esquema ? PUERTO_DE_ESQUEMA[esquema] ?? null : null;
  return conHost(c, { clase: "url", esquema, puerto, ruta: ruta.replace(/\/+$/, "") || "/" });
}

/** Interpreta un objetivo o un ítem del alcance. Null si no se entiende. */
function leer(crudo, { comodin = false } = {}) {
  const s = String(crudo ?? "").trim();
  if (!s || s.length > 2000) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return leerUrl(s, true);
  const rango = rangoCidr(s) || rangoConGuion(s);
  if (rango) return rango.ilegible ? null : rango;
  if (s.startsWith("*.")) {
    const c = comodin ? canonizarHost(s.slice(2)) : null;
    return c?.host ? { clase: "host", host: c.host, comodin: true, puerto: null } : null;
  }
  const corchetes = /^\[([^\]]+)\](?::(\d{1,5})(?:\/(?:tcp|udp|sctp))?)?$/i.exec(s);
  const conPuerto = /^([^:/]+):(\d{1,5})(?:\/(?:tcp|udp|sctp))?$/i.exec(s);
  const m = corchetes || conPuerto;
  if (m) {
    const c = canonizarHost(m[1]);
    const puerto = m[2] ? Number(m[2]) : null;
    if (!c || (puerto !== null && (puerto < 1 || puerto > 65535))) return null;
    return conHost(c, { clase: c.ip ? "ip" : "host", puerto });
  }
  if (s.includes("/")) return leerUrl(s, false);
  const c = canonizarHost(s);
  return c && conHost(c, { clase: c.ip ? "ip" : "host", puerto: null });
}

const tieneIp = (x) => x.ini !== undefined;
function mismoHost(t, item) {
  if (tieneIp(t) !== tieneIp(item)) return false;
  if (tieneIp(t)) return t.v === item.v;
  return item.comodin ? t.host.endsWith(`.${item.host}`) : t.host === item.host;
}
const rutaDentro = (ruta, base) => base === "/" || ruta === base || ruta.startsWith(`${base}/`);

/** ¿El ítem cubre por completo al objetivo? */
function cubre(item, t) {
  if (!mismoHost(t, item)) return false;
  if (tieneIp(t) && (t.ini < item.ini || t.fin > item.fin)) return false;
  if (item.clase !== "url") return item.puerto === null || item.puerto === t.puerto;
  if (t.clase !== "url") return item.ruta === "/" && (t.puerto === null || item.puerto === null || t.puerto === item.puerto);
  if (item.esquema && t.esquema && item.esquema !== t.esquema) return false;
  if (item.puerto !== null && t.puerto !== null && item.puerto !== t.puerto) return false;
  return rutaDentro(t.ruta, item.ruta);
}

/** ¿El objetivo toca algo excluido? Para rangos alcanza con una dirección en común. */
function toca(item, t) {
  if (!mismoHost(t, item)) return false;
  if (tieneIp(t) && (t.fin < item.ini || t.ini > item.fin)) return false;
  if (item.clase !== "url") return item.puerto === null || item.puerto === t.puerto;
  if (item.ruta === "/") return t.puerto === null || item.puerto === null || t.puerto === item.puerto;
  // Sin mirar esquema ni puerto: la misma ruta por http y por https suele ser la misma aplicación.
  return t.clase === "url" && rutaDentro(t.ruta, item.ruta);
}

const normal = (s) => String(s ?? "").trim().toLocaleLowerCase("es");
const partir = (s) => String(s ?? "").split(/[\s,;]+/).filter(Boolean);
const ES_LIBRE = new Set(["application", "other"]);

function preparar(items, dentro) {
  const red = [], libres = new Set();
  let ilegible = null;
  for (const it of items) {
    if (Boolean(Number(it.in_scope)) !== dentro) continue;
    if (ES_LIBRE.has(it.type)) libres.add(normal(it.value));
    if (ES_LIBRE.has(it.type) && dentro) continue;
    for (const parte of partir(it.value)) {
      const x = leer(parte, { comodin: true });
      if (x) red.push(x);
      else if (!ES_LIBRE.has(it.type)) ilegible = it.value;
    }
  }
  return { red, libres, ilegible };
}

/**
 * Evalúa uno o varios objetivos (separados por espacios, comas o punto y coma).
 * Devuelve { dentro, motivo }: todos tienen que estar dentro.
 */
function evaluar(objetivo, items) {
  const texto = String(objetivo ?? "").trim();
  if (!texto) return { dentro: false, motivo: "No se indicó un objetivo." };
  const si = preparar(items, true), no = preparar(items, false);
  if (no.libres.has(normal(texto))) return { dentro: false, motivo: `"${texto}" está excluido del alcance.` };
  if (no.ilegible) return { dentro: false, motivo: `No se puede interpretar la exclusión "${no.ilegible}": hay que corregirla en el alcance.` };
  if (si.libres.has(normal(texto))) return { dentro: true, motivo: null };
  if (!si.red.length && !si.libres.size) return { dentro: false, motivo: "El engagement no tiene objetivos dentro de alcance." };
  for (const parte of partir(texto)) {
    const t = leer(parte);
    if (!t) return { dentro: false, motivo: `No se puede interpretar el objetivo "${parte}".` };
    if (no.red.some((e) => toca(e, t))) return { dentro: false, motivo: `"${parte}" está excluido del alcance.` };
    if (!si.red.some((e) => cubre(e, t))) return { dentro: false, motivo: `"${parte}" no está en el alcance.` };
  }
  return { dentro: true, motivo: null };
}

module.exports = { evaluar, leer };
