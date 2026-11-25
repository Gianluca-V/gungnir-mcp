"use strict";
/**
 * Attack Map para agentes: equipos, puertos y pivotes.
 *
 * Solo agrega o completa lo que está vacío. Lo que cargó una persona no se pisa ni se borra: lo que no se
 * aplicó por eso se informa en `conservados`.
 */
const { v4: uuidv4 } = require("uuid");
const H = require("./hallazgos");
const { leer } = require("./alcance");
const { ErrorHttp, texto, opcion } = require("./comun");

const SISTEMAS = ["windows", "windowsserver", "linux", "ubuntu", "debian", "kali", "parrot", "arch", "fedora", "redhat", "macos",
  "router", "server", "firewall", "switch", "printer", "nas", "iot", "camera", "android", "ios", "freebsd", "other"];
const MAX_EQUIPOS = 50;
const MAX_PUERTOS = 1000;
const TOPE_MAPA = 2000;
const MAX_PENDIENTES = 50;

function soloCampos(o, admite, que) {
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new ErrorHttp(400, `Cada ${que} tiene que ser un objeto.`);
  const sobran = Object.keys(o).filter((k) => !admite.includes(k));
  if (sobran.length) throw new ErrorHttp(400, `Campos no admitidos en ${que}: ${sobran.join(", ")}. Se admiten: ${admite.join(", ")}.`);
}

/** Una IP en su forma canónica, desde el número que da el control de alcance. */
function textoDeIp({ v, ini }) {
  if (v === 4) return [24n, 16n, 8n, 0n].map((b) => (ini >> b) & 255n).join(".");
  const grupos = Array.from({ length: 8 }, (_, k) => ((ini >> BigInt(112 - 16 * k)) & 0xffffn).toString(16)).join(":");
  return new URL(`http://[${grupos}]/`).hostname.slice(1, -1);
}

/** En qué columna va un objetivo (una sola IP, un nombre o una URL) y cómo se escribe. Null si no sirve. */
function ubicar(objetivo) {
  const x = leer(objetivo);
  if (x?.clase === "url" && /^https?:\/\//i.test(objetivo)) {
    const u = new URL(objetivo);
    return u.username || u.password ? null : { columna: "url_address", valor: u.href };
  }
  if (x?.clase === "ip" && x.puerto === null && x.ini === x.fin && !objetivo.includes("/")) return { columna: "ip_address", valor: textoDeIp(x) };
  if (x?.clase === "host" && x.puerto === null && !x.comodin) return { columna: "fqdn", valor: x.host };
  return null;
}
/** Con qué se reconoce un equipo. Lo que ya está en el mapa lo pudo escribir una persona de cualquier forma. */
const claveDe = (n) => ubicar(n)?.valor ?? n.trim().toLowerCase();
/** Un texto que no depende del orden de las claves: MySQL las reordena al guardar JSON. */
const canonico = (v) => JSON.stringify(v, (_, x) => (x && typeof x === "object" && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : 1))) : x));
/** Si dos pedidos piden lo mismo, en cualquier orden. */
function mismoPedido(a, b) {
  const ordenar = ({ equipos }) => canonico(equipos.map((e) => canonico({ ...e, objetivo: claveDe(e.objetivo), ...(e.desde ? { desde: claveDe(e.desde) } : {}), puertos: (e.puertos || []).map(canonico).sort() })).sort());
  return ordenar(a) === ordenar(b);
}

function validarPuertos(lista) {
  if (lista === undefined) return [];
  if (!Array.isArray(lista)) throw new ErrorHttp(400, `"puertos" tiene que ser una lista.`);
  const vistos = new Set();
  return lista.map((p) => {
    soloCampos(p, ["puerto", "protocolo", "servicio", "producto", "version"], "puerto");
    if (!Number.isInteger(p.puerto) || p.puerto < 1 || p.puerto > 65535) throw new ErrorHttp(400, `"puerto" tiene que ser un entero entre 1 y 65535.`);
    const d = { puerto: p.puerto, protocolo: opcion(p.protocolo, "protocolo", ["tcp", "udp", "sctp"]) || "tcp" };
    if (vistos.has(`${d.puerto}/${d.protocolo}`)) throw new ErrorHttp(400, `El puerto ${d.puerto}/${d.protocolo} está repetido.`);
    vistos.add(`${d.puerto}/${d.protocolo}`);
    for (const [k, max] of [["servicio", 100], ["producto", 255], ["version", 255]]) {
      const v = texto(p[k], k, { max });
      if (v) d[k] = v;
    }
    return d;
  });
}

/** Valida y deja los campos siempre en el mismo orden, para poder comparar dos pedidos. */
function validar(b) {
  soloCampos(b, ["equipos"], "pedido");
  if (!Array.isArray(b.equipos) || !b.equipos.length || b.equipos.length > MAX_EQUIPOS) throw new ErrorHttp(400, `"equipos" tiene que ser una lista de 1 a ${MAX_EQUIPOS}.`);
  const vistos = new Set();
  let total = 0;
  const equipos = b.equipos.map((e) => {
    soloCampos(e, ["objetivo", "os_type", "notas", "comprometido", "desde", "puertos"], "equipo");
    const objetivo = texto(e.objetivo, "objetivo", { max: 500, obligatorio: true });
    const lugar = ubicar(objetivo);
    if (!lugar) throw new ErrorHttp(400, `Hay un equipo que no sirve: "objetivo" tiene que ser una sola IP, un nombre o una URL, sin puerto ni credenciales. Los puertos van en "puertos".`);
    const { columna, valor } = lugar;
    if (valor.length > (columna === "fqdn" ? 255 : 1024)) throw new ErrorHttp(400, `"${valor.slice(0, 60)}..." es demasiado largo.`);
    if (vistos.has(valor)) throw new ErrorHttp(400, `El equipo "${valor}" está repetido.`);
    vistos.add(valor);
    const puertos = validarPuertos(e.puertos);
    total += puertos.length;
    if (puertos.length && columna === "url_address") throw new ErrorHttp(400, `Una URL no lleva "puertos": cargalos en su IP o en su nombre.`);
    if (e.comprometido !== undefined && e.comprometido !== true) throw new ErrorHttp(400, `"comprometido" solo admite verdadero: no se desmarca desde acá.`);
    const d = { objetivo };
    const os = opcion(e.os_type, "os_type", SISTEMAS), notas = texto(e.notas, "notas", { max: 5000 }), desde = texto(e.desde, "desde", { max: 500 });
    if (os) d.os_type = os;
    if (notas) d.notas = notas;
    if (e.comprometido) d.comprometido = true;
    if (desde) d.desde = desde;
    if (puertos.length) d.puertos = puertos;
    return d;
  });
  if (total > MAX_PUERTOS) throw new ErrorHttp(400, `Hasta ${MAX_PUERTOS} puertos por pedido.`);
  H.exigirSinMarcas(equipos);
  return { equipos };
}

/** Lo que tiene que estar en alcance. Con puertos se mira cada uno: puede haber uno excluido y otros no. */
function objetivosDe({ objetivo, puertos }) {
  if (!puertos?.length) return [objetivo];
  const { valor } = ubicar(objetivo);
  const host = valor.includes(":") ? `[${valor}]` : valor;
  return puertos.map((p) => `${host}:${p.puerto}/${p.protocolo}`);
}

const nombresDe = (t) => [t.ip_address, t.fqdn, t.url_address].filter(Boolean);

/**
 * Lo guarda. Quien llama toma antes el engagement y no leyó nada sin bloqueo, así ve lo último que guardaron
 * otros agentes. Una persona puede guardar a la vez: por eso cada cambio se condiciona a que siga vacío, y no
 * se bloquea más que la fila que se toca.
 */
async function aplicar(tx, engagementId, { equipos }) {
  const filas = await tx.qRows("SELECT id,ip_address,fqdn,url_address,os_type,owned,jumped_from_id,notes FROM engagement_targets WHERE engagement_id=? ORDER BY created_at, id", [engagementId]);
  const porNombre = new Map(), porId = new Map();
  const sumar = (t) => { porId.set(t.id, t); for (const n of nombresDe(t)) if (!porNombre.has(claveDe(n))) porNombre.set(claveDe(n), t); };
  filas.forEach(sumar);
  const r = { equipos_nuevos: 0, equipos_completados: 0, puertos_nuevos: 0, puertos_completados: 0, pivotes_nuevos: 0, conservados: [] };
  /** Escribe una columna si sigue vacía. mysql2 cuenta las filas que cumplen la condición. */
  const siVacia = async (tabla, columna, valor, id, vacia) => (await tx.qRun(`UPDATE ${tabla} SET ${columna}=? WHERE id=? AND ${vacia}`, [valor, id]))[0].affectedRows > 0;
  const pares = [];
  for (const e of equipos) {
    const conservar = (campo) => r.conservados.push({ objetivo: e.objetivo, campo });
    const { columna, valor } = ubicar(e.objetivo);
    let t = porNombre.get(valor), nuevo = false;
    if (!t) {
      if (porId.size >= TOPE_MAPA) throw new ErrorHttp(409, `El mapa ya tiene ${TOPE_MAPA} equipos.`);
      t = { id: uuidv4(), ip_address: null, fqdn: null, url_address: null, os_type: e.os_type || "other", owned: e.comprometido ? 1 : 0, jumped_from_id: null, notes: e.notas || null, [columna]: valor };
      await tx.qRun("INSERT INTO engagement_targets (id,engagement_id,ip_address,fqdn,url_address,os_type,notes,owned) VALUES (?,?,?,?,?,?,?,?)",
        [t.id, engagementId, t.ip_address, t.fqdn, t.url_address, t.os_type, t.notes, t.owned]);
      sumar(t);
      nuevo = true;
      r.equipos_nuevos++;
    } else {
      let completado = false;
      for (const [campo, columna2, v, vacia] of [["os_type", "os_type", e.os_type, "os_type='other'"], ["notas", "notes", e.notas, "(notes IS NULL OR notes='')"]]) {
        if (!v || t[columna2] === v) continue;
        if (await siVacia("engagement_targets", columna2, v, t.id, vacia)) { t[columna2] = v; completado = true; } else conservar(campo);
      }
      if (e.comprometido && !t.owned && await siVacia("engagement_targets", "owned", 1, t.id, "owned=0")) { t.owned = 1; completado = true; }
      if (completado) r.equipos_completados++;
    }
    if (e.puertos?.length) await aplicarPuertos(tx, engagementId, t, nuevo, e.puertos, r, conservar, siVacia);
    if (e.desde) pares.push([e, t, conservar]);
  }
  // Los pivotes van al final: el origen puede venir en el mismo pedido.
  for (const [e, t, conservar] of pares) {
    const origen = porNombre.get(claveDe(e.desde));
    if (!origen) throw new ErrorHttp(422, `El origen del pivote a "${e.objetivo}" no está en el mapa: cargalo antes o en el mismo pedido.`);
    if (t.jumped_from_id) {
      if (t.jumped_from_id !== origen.id) conservar("desde");
      continue;
    }
    for (let o = origen, vistos = new Set(); o && !vistos.has(o.id); o = porId.get(o.jumped_from_id)) {
      if (o.id === t.id) throw new ErrorHttp(422, `"${e.objetivo}" no puede salir de "${e.desde}": formaría un ciclo.`);
      vistos.add(o.id);
    }
    if (await siVacia("engagement_targets", "jumped_from_id", origen.id, t.id, "jumped_from_id IS NULL").catch(seBorro)) {
      t.jumped_from_id = origen.id;
      r.pivotes_nuevos++;
    } else conservar("desde");
  }
  return r;
}

/** Alguien borró el equipo mientras tanto: se deshace todo y se pide repetir. */
function seBorro(e) {
  if (String(e?.code).startsWith("ER_NO_REFERENCED_ROW")) throw new ErrorHttp(409, "El mapa cambió mientras se guardaba y no se guardó nada. Volvé a leerlo y repetí el pedido.");
  throw e;
}

async function aplicarPuertos(tx, engagementId, t, nuevo, puertos, r, conservar, siVacia) {
  const estaban = new Map((nuevo ? [] : await tx.qRows("SELECT id,port_number,protocol,state,service_name,product,version FROM target_ports WHERE target_id=?", [t.id])).map((p) => [`${p.port_number}/${p.protocol}`, p]));
  for (const p of puertos) {
    const nombre = `${p.puerto}/${p.protocolo}`, ya = estaban.get(nombre);
    if (!ya) {
      // Si alguien lo cargó recién, queda lo suyo y se completa lo que dejó vacío.
      const lleno = (k) => `${k}=IF(state='open',COALESCE(NULLIF(${k},''),VALUES(${k})),${k})`;
      await tx.qRun(
        `INSERT INTO target_ports (id,target_id,engagement_id,port_number,protocol,service_name,product,version) VALUES (?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE ${["service_name", "product", "version"].map(lleno).join(",")}`,
        [uuidv4(), t.id, engagementId, p.puerto, p.protocolo, p.servicio ?? null, p.producto ?? null, p.version ?? null]).catch(seBorro);
      r.puertos_nuevos++;
      continue;
    }
    if (ya.state !== "open") { conservar(`puerto ${nombre}: estado ${ya.state}`); continue; }
    let completado = false;
    for (const [k, columna] of [["servicio", "service_name"], ["producto", "product"], ["version", "version"]]) {
      if (!p[k] || p[k] === ya[columna]) continue;
      if (await siVacia("target_ports", columna, p[k], ya.id, `state='open' AND (${columna} IS NULL OR ${columna}='')`)) completado = true;
      else conservar(`puerto ${nombre}: ${k}`);
    }
    if (completado) r.puertos_completados++;
  }
}

module.exports = { SISTEMAS, MAX_PENDIENTES, validar, objetivosDe, aplicar, nombresDe, mismoPedido, canonico };
