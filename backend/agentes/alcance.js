"use strict";
/**
 * Decide si un objetivo está dentro del alcance de un engagement.
 *
 * Reglas:
 *  - Sin ítems dentro de alcance, todo queda fuera.
 *  - Una exclusión gana siempre. Un rango que toca una exclusión queda fuera entero, y un objetivo sin
 *    puerto toca a una exclusión con puerto.
 *  - Un dominio vale solo para sí mismo; los subdominios se piden con "*.dominio".
 *  - Una URL acota esquema, puerto y prefijo de ruta (por segmento completo). Al excluir, la ruta se
 *    compara sin mayúsculas, sin parámetros de segmento (";x=1") y por http o https.
 *  - Lo que no se puede interpretar queda fuera. Si lo ilegible es una exclusión de red, nada queda
 *    dentro: no se puede saber qué excluye.
 *
 * No resuelve DNS: compara lo que se declara con lo que está cargado. Es un control de registro, no
 * un cortafuegos.
 */

const ES_URL = /^[a-z][a-z0-9+.-]*:\/\//i;
const MAX32 = (1n << 32n) - 1n;
const HOST = /^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62})(?:\.[a-z0-9_][a-z0-9_-]{0,62})*$/;
// "10.0.0.x", "10.0.0-1.1-20", "10.x.x.x": direcciones mal escritas que pasarían por nombres. Con más de
// cuatro partes sí es un nombre (10.0.0.5.nip.io).
const DIRECCION_ROTA = /^\d{1,3}(?:-\d{1,3})?\.(?:\d{1,3}(?:-\d{1,3})?\.[^.]+(?:\.[^.]+)?|(?:x{1,3}|n)(?:\.(?:\d{1,3}|x{1,3}|n))*)$/;
const PUERTO_DE_ESQUEMA = {
  http: 80, https: 443, ws: 80, wss: 443, ftp: 21, ftps: 990, ssh: 22, sftp: 22, telnet: 23, smb: 445, rdp: 3389, ldap: 389, ldaps: 636,
  mysql: 3306, postgres: 5432, postgresql: 5432, redis: 6379, mongodb: 27017, vnc: 5900,
};

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
  // 010.1.1.1 es 8.1.1.1 para unas herramientas y 10.1.1.1 para otras, y un número suelto puede ser un
  // resto de "10.0.0.5,6,7": no se adivina. Una IPv4 se escribe con sus cuatro partes en decimal.
  if (/^(?:0x[\da-f]*|\d+)(?:\.(?:0x[\da-f]*|\d+))*$/.test(h) && ipv4ANumero(h) === null) return null;
  if (h.includes(":") && !h.startsWith("[")) h = `[${h}]`;
  let canon;
  try { canon = new URL(`http://${h}/`).hostname; } catch { return null; }
  if (canon.startsWith("[")) {
    const n = ipv6ANumero(canon.slice(1, -1));
    if (n === null) return null;
    return (n >> 32n) === 0xffffn ? { ip: { v: 4, n: n & MAX32 } } : { ip: { v: 6, n } };
  }
  const n4 = ipv4ANumero(canon);
  // 255.255.255.0 y 0.0.0.255 son máscaras, no equipos.
  if (n4 !== null) return n4 >> 24n === 255n || n4 >> 24n === 0n ? null : { ip: { v: 4, n: n4 } };
  return HOST.test(canon) && !DIRECCION_ROTA.test(canon) ? { host: canon } : null;
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

function leerUrl(s, conEsquema, comodin) {
  let u;
  try { u = new URL(conEsquema ? s : `http://${s}`); } catch { return null; }
  const c = canonizarHost(u.hostname.replace(/^\[|\]$/g, ""));
  if (!c) return null;
  let ruta;
  try { ruta = decodeURIComponent(u.pathname); } catch { return null; }
  // Tras decodificar y sacar los parámetros de segmento ("..;x=1") no puede quedar nada codificado ni que
  // suba de directorio: cada servidor lo lee distinto.
  const segmentos = ruta.split("/").map((p) => p.split(";")[0]);
  if (/[\\\x00-\x1f]|%[\da-f]{2}/i.test(ruta) || segmentos.some((p) => p === ".." || p === ".")) return null;
  // "10.0.0.0/255.255.255.0" es una red con máscara, no una ruta.
  if (!conEsquema && /^\/\d{1,3}(?:\.\d{1,3}){3}$/.test(ruta)) return null;
  ruta = segmentos.join("/").replace(/\/{2,}/g, "/");
  if (comodin) ruta = ruta.replace(/\/\*{1,2}$/, "");
  if (comodin && ruta.includes("*")) return null;
  const esquema = conEsquema ? u.protocol.slice(0, -1) : null;
  const puerto = u.port ? Number(u.port) : esquema ? PUERTO_DE_ESQUEMA[esquema] ?? null : null;
  return conHost(c, { clase: "url", esquema, puerto, puertoExplicito: Boolean(u.port), ruta: ruta.replace(/\/+$/, "") || "/" });
}

/** Interpreta un objetivo o un ítem del alcance. Null si no se entiende. */
function leer(crudo, { comodin = false } = {}) {
  const s = String(crudo ?? "").trim();
  // Una ruta suelta ("/admin") no dice de qué sitio es.
  if (!s || s.length > 2000 || s.startsWith("/") || /[\\\x00-\x1f]/.test(s)) return null;
  if (ES_URL.test(s)) return leerUrl(s, true, comodin);
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
  if (s.includes("/")) return leerUrl(s, false, comodin);
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
  if (item.clase !== "url") return item.puerto === null || t.puerto === null || item.puerto === t.puerto;
  if (item.ruta !== "/") return t.clase === "url" && rutaDentro(t.ruta.toLowerCase(), item.ruta.toLowerCase());
  // Sin puerto escrito, excluir el sitio vale por http y por https.
  return t.puerto === null || item.puerto === null || t.puerto === item.puerto || (!item.puertoExplicito && [80, 443].includes(t.puerto));
}

const normal = (s) => String(s ?? "").trim().toLocaleLowerCase("es");
/** Separa por espacios, comas y punto y coma, menos los que son parte de una URL. */
const partir = (s) => String(s ?? "").split(/\s+/)
  .flatMap((p) => p.replace(/[,;]+$/, "").split(ES_URL.test(p) ? /[,;](?=[a-z][a-z0-9+.-]*:\/\/)/i : /[,;]+/)).filter(Boolean);
const ES_LIBRE = new Set(["application", "other"]);
const ES_DE_IP = new Set(["ip", "cidr"]);

function preparar(items, dentro) {
  const red = [], libres = new Set();
  let ilegible = null;
  for (const it of items) {
    if (Boolean(Number(it.in_scope)) !== dentro) continue;
    if (ES_LIBRE.has(it.type)) libres.add(normal(it.value));
    if (ES_LIBRE.has(it.type) && dentro) continue;
    const partes = partir(it.value);
    for (const parte of partes) {
      const x = leer(parte, { comodin: true });
      // En una lista, un nombre sin puntos es casi seguro una palabra ("10.0.0.5 a 10.0.0.20"), y un ítem
      // de tipo IP o CIDR solo puede traer direcciones.
      const sospechoso = x && ((partes.length > 1 && x.host && !x.host.includes(".")) || (ES_DE_IP.has(it.type) && x.clase !== "ip"));
      if (x && !(sospechoso && !ES_LIBRE.has(it.type))) red.push(x);
      else if (!ES_LIBRE.has(it.type)) ilegible = it.value;
    }
  }
  return { red, libres, ilegible };
}

/** Prepara un alcance para evaluar muchos objetivos sin volver a leerlo. */
function evaluador(items) {
  const si = preparar(items, true), no = preparar(items, false);
  return (objetivo) => evaluarPreparado(objetivo, si, no);
}

/**
 * Evalúa uno o varios objetivos (separados por espacios, comas o punto y coma).
 * Devuelve { dentro, motivo }: todos tienen que estar dentro.
 */
const evaluar = (objetivo, items) => evaluador(items)(objetivo);

function evaluarPreparado(objetivo, si, no) {
  const texto = String(objetivo ?? "").trim();
  if (!texto) return { dentro: false, motivo: "No se indicó un objetivo." };
  if (no.libres.has(normal(texto))) return { dentro: false, excluido: true, motivo: `"${texto}" está excluido del alcance.` };
  if (no.ilegible) return { dentro: false, motivo: `No se puede interpretar la exclusión "${no.ilegible}": hay que corregirla en el alcance.` };
  const partes = partir(texto).map((parte) => [parte, leer(parte)]);
  const excluida = partes.find(([, t]) => t && no.red.some((e) => toca(e, t)));
  if (excluida) return { dentro: false, excluido: true, motivo: `"${excluida[0]}" está excluido del alcance.` };
  if (si.libres.has(normal(texto))) return { dentro: true, motivo: null };
  if (!si.red.length && !si.libres.size) return { dentro: false, motivo: "El engagement no tiene objetivos dentro de alcance." };
  if (!partes.length) return { dentro: false, motivo: "No se indicó un objetivo." };
  for (const [parte, t] of partes) {
    if (!t) return { dentro: false, motivo: `No se puede interpretar el objetivo "${parte}".` };
    if (!si.red.some((e) => cubre(e, t))) return { dentro: false, motivo: `"${parte}" no está en el alcance.` };
  }
  return { dentro: true, motivo: null };
}

module.exports = { evaluar, evaluador, leer };
