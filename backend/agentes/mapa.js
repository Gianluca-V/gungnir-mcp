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

/** En qué columna va un objetivo: una sola IP, un nombre o una URL. */
function ubicar(objetivo) {
  const x = leer(objetivo);
  if (x?.clase === "url" && /^https?:\/\//i.test(objetivo)) return { columna: "url_address", valor: objetivo };
  const limpio = objetivo.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (x?.clase === "ip" && x.puerto === null && x.ini === x.fin && !objetivo.includes("/")) return { columna: "ip_address", valor: limpio };
  if (x?.clase === "host" && x.puerto === null && !x.comodin) return { columna: "fqdn", valor: limpio };
  throw new ErrorHttp(400, `"${objetivo}" no sirve como equipo: tiene que ser una sola IP, un nombre o una URL, sin puerto. Los puertos van en "puertos".`);
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
    const { columna, valor } = ubicar(objetivo);
    if (valor.length > (columna === "fqdn" ? 255 : 1024)) throw new ErrorHttp(400, `"${objetivo.slice(0, 60)}..." es demasiado largo.`);
    if (vistos.has(valor.toLowerCase())) throw new ErrorHttp(400, `El equipo "${objetivo}" está repetido.`);
    vistos.add(valor.toLowerCase());
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

/** Lo guarda. Quien llama ya tomó el engagement, así dos pedidos iguales no se cruzan. */
async function aplicar(tx, engagementId, { equipos }) {
  const filas = await tx.qRows("SELECT id,ip_address,fqdn,url_address,os_type,owned,jumped_from_id,notes FROM engagement_targets WHERE engagement_id=?", [engagementId]);
  const porNombre = new Map(), porId = new Map();
  const sumar = (t) => { porId.set(t.id, t); for (const n of nombresDe(t)) if (!porNombre.has(n.toLowerCase())) porNombre.set(n.toLowerCase(), t); };
  filas.forEach(sumar);
  const r = { equipos_nuevos: 0, equipos_completados: 0, puertos_nuevos: 0, pivotes_nuevos: 0, conservados: [] };
  const pares = [];
  for (const e of equipos) {
    const { columna, valor } = ubicar(e.objetivo);
    let t = porNombre.get(valor.toLowerCase());
    if (!t) {
      if (porId.size >= TOPE_MAPA) throw new ErrorHttp(409, `El mapa ya tiene ${TOPE_MAPA} equipos.`);
      t = { id: uuidv4(), ip_address: null, fqdn: null, url_address: null, os_type: e.os_type || "other", owned: e.comprometido ? 1 : 0, jumped_from_id: null, notes: e.notas || null, [columna]: valor };
      await tx.qRun("INSERT INTO engagement_targets (id,engagement_id,ip_address,fqdn,url_address,os_type,notes,owned) VALUES (?,?,?,?,?,?,?,?)",
        [t.id, engagementId, t.ip_address, t.fqdn, t.url_address, t.os_type, t.notes, t.owned]);
      sumar(t);
      r.equipos_nuevos++;
    } else {
      const cambios = {};
      const completar = (columna2, campo, valor2, vacio) => {
        if (!valor2 || t[columna2] === valor2) return;
        if (vacio) cambios[columna2] = valor2; else r.conservados.push({ objetivo: e.objetivo, campo });
      };
      completar("os_type", "os_type", e.os_type, !t.os_type || t.os_type === "other");
      completar("notes", "notas", e.notas, !t.notes);
      if (e.comprometido && !t.owned) cambios.owned = 1;
      const k = Object.keys(cambios);
      if (k.length) {
        await tx.qRun(`UPDATE engagement_targets SET ${k.map((c) => `${c}=?`).join(",")} WHERE id=?`, [...Object.values(cambios), t.id]);
        Object.assign(t, cambios);
        r.equipos_completados++;
      }
    }
    const yaEstan = e.puertos ? new Set((await tx.qRows("SELECT port_number, protocol FROM target_ports WHERE target_id=?", [t.id])).map((p) => `${p.port_number}/${p.protocol}`)) : null;
    for (const p of e.puertos || []) {
      await tx.qRun(
        `INSERT INTO target_ports (id,target_id,engagement_id,port_number,protocol,service_name,product,version) VALUES (?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE service_name=COALESCE(NULLIF(service_name,''),VALUES(service_name)), product=COALESCE(NULLIF(product,''),VALUES(product)), version=COALESCE(NULLIF(version,''),VALUES(version))`,
        [uuidv4(), t.id, engagementId, p.puerto, p.protocolo, p.servicio ?? null, p.producto ?? null, p.version ?? null]);
      if (!yaEstan.has(`${p.puerto}/${p.protocolo}`)) r.puertos_nuevos++;
    }
    if (e.desde) pares.push([e, t]);
  }
  // Los pivotes van al final: el origen puede venir en el mismo pedido.
  for (const [e, t] of pares) {
    const origen = porNombre.get(e.desde.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "")) || porNombre.get(e.desde.toLowerCase());
    if (!origen) throw new ErrorHttp(422, `"${e.desde}" no está en el mapa: cargalo antes o en el mismo pedido.`);
    if (t.jumped_from_id) {
      if (t.jumped_from_id !== origen.id) r.conservados.push({ objetivo: e.objetivo, campo: "desde" });
      continue;
    }
    for (let o = origen, vistos = new Set(); o && !vistos.has(o.id); o = porId.get(o.jumped_from_id)) {
      if (o.id === t.id) throw new ErrorHttp(422, `"${e.objetivo}" no puede salir de "${e.desde}": formaría un ciclo.`);
      vistos.add(o.id);
    }
    await tx.qRun("UPDATE engagement_targets SET jumped_from_id=? WHERE id=?", [origen.id, t.id]);
    t.jumped_from_id = origen.id;
    r.pivotes_nuevos++;
  }
  return r;
}

module.exports = { SISTEMAS, MAX_PENDIENTES, validar, objetivosDe, aplicar, nombresDe };
