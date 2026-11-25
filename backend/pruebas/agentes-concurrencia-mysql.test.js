/**
 * Agentes y personas a la vez: el server.js real contra un MySQL o MariaDB de verdad. Va aparte, con su
 * propio servidor, porque hace muchos pedidos del panel.
 *
 *   GUNGNIR_PRUEBA_DB=mysql://usuario:clave@127.0.0.1:3306/base_de_prueba npm test
 *
 * Sin la variable se saltea. ⛔ Nunca apuntarla a una base con datos.
 */
"use strict";
const { test, describe, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const net = require("node:net");
const path = require("node:path");
const jwt = require("jsonwebtoken");
const URL_DB = process.env.GUNGNIR_PRUEBA_DB;

const SECRETO = "pruebas-" + "0123456789abcdef".repeat(4);
const uid = () => crypto.randomUUID();

describe("agentes y personas a la vez", { skip: !URL_DB && "sin GUNGNIR_PRUEBA_DB" }, () => {
  let pool, hijo, base, salida = "";
  const suf = crypto.randomBytes(4).toString("hex");
  const USUARIO = uid(), CLIENTE = uid(), E = [uid(), uid(), uid()], keys = [];
  const sesion = jwt.sign({ id: USUARIO, role: "admin", tv: 0 }, SECRETO);
  const sql = async (q, p) => (await pool.query(q, p))[0];
  async function pedir(metodo, ruta, bearer, body) {
    const r = await fetch(base + ruta, { method: metodo, headers: { Authorization: `Bearer ${bearer}`, ...(body ? { "Content-Type": "application/json" } : {}) }, body: body && JSON.stringify(body) });
    const texto = await r.text();
    let json = null; try { json = JSON.parse(texto); } catch {}
    return { status: r.status, texto, json, que: `${metodo} ${ruta.replace(/[0-9a-f-]{36}/g, ":id")}` };
  }
  const panel = (m, r, b) => pedir(m, `/api${r}`, sesion, b);
  const mapa = (i, equipos) => pedir("POST", `/api/agente/v1/engagements/${E[i]}/mapa`, keys[i], { equipos });
  const nuevos = (i, n) => Array.from({ length: 5 }, (_, k) => ({ objetivo: `10.${10 + i}.${n}.${k + 1}`, os_type: "linux", puertos: [{ puerto: 22 }, { puerto: 80 }] }));
  const repetir = async (n, fn) => { const r = []; for (let i = 0; i < n; i++) r.push(await fn(i)); return r; };
  const malos = (rs) => rs.flat().filter((x) => x.status >= 500).map((x) => `${x.que}: ${x.status} ${salida.split("\n").filter((l) => /Error|rror:/.test(l)).slice(-3).join(" | ")}`);

  before(async () => {
    const mysql = require("mysql2/promise");
    const u = new URL(URL_DB);
    const puerto = await new Promise((ok) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => ok(p)); }); });
    hijo = spawn(process.execPath, ["server.js"], {
      cwd: path.join(__dirname, ".."),
      env: { ...process.env, PORT: String(puerto), NODE_ENV: "test", JWT_SECRET: SECRETO, TRUST_PROXY: "false", VULN_FUENTES_EXTERNAS: "0",
             DB_HOST: u.hostname, DB_PORT: u.port || "3306", DB_USER: decodeURIComponent(u.username), DB_PASSWORD: decodeURIComponent(u.password), DB_NAME: u.pathname.slice(1) },
    });
    hijo.stdout.on("data", (d) => { salida += d; }); hijo.stderr.on("data", (d) => { salida += d; });
    base = `http://127.0.0.1:${puerto}`;
    for (const limite = Date.now() + 60000; ;) {
      if (hijo.exitCode !== null) throw new Error(salida);
      try { if ((await fetch(`${base}/api/health`)).ok) break; } catch {}
      if (Date.now() > limite) throw new Error("no arrancó:\n" + salida);
      await new Promise((r) => setTimeout(r, 200));
    }
    pool = mysql.createPool({ uri: URL_DB, connectionLimit: 3 });
    await sql("INSERT INTO users (id,username,email,password_hash,role) VALUES (?,?,?,?,?)", [USUARIO, `conc-${suf}`, `conc-${suf}@x`, "x", "admin"]);
    await sql("INSERT INTO clients (id,name) VALUES (?,?)", [CLIENTE, "Cliente Ficticio"]);
    for (const [i, e] of E.entries()) {
      await sql("INSERT INTO engagements (id,client_id,title,status) VALUES (?,?,?,?)", [e, CLIENTE, `Concurrencia ${i}`, "in_progress"]);
      await sql("INSERT INTO phases (id,engagement_id,phase_type) VALUES (?,?,'scanning')", [uid(), e]);
      await sql("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,'cidr',?,1)", [uid(), e, `10.${10 + i}.0.0/16`]);
      assert.equal((await panel("PUT", `/agentes/engagements/${e}`, { nivel_max: "escritura" })).status, 200);
      keys.push((await panel("POST", "/agentes/keys", { nombre: `conc ${i}`, nivel_max: "escritura", engagements: [e] })).json.key);
    }
  });
  after(async () => {
    try {
      if (pool) {
        await sql("DELETE FROM engagements WHERE client_id=?", [CLIENTE]);
        await sql("DELETE FROM clients WHERE id=?", [CLIENTE]);
        await sql("DELETE FROM users WHERE id=?", [USUARIO]);
      }
    } finally {
      if (pool) await pool.end();
      if (hijo && hijo.exitCode === null) await new Promise((ok) => { hijo.on("exit", ok); hijo.kill("SIGKILL"); });
    }
  });

  test("🔴 agentes en engagements distintos no se estorban", async () => {
    const r = await Promise.all(E.map((_, i) => repetir(40, (n) => mapa(i, nuevos(i, n)))));
    assert.deepEqual(malos(r), []);
    assert.ok(r.flat().every((x) => x.status === 200));
    for (const e of E) assert.equal((await sql("SELECT COUNT(*) AS n FROM engagement_targets WHERE engagement_id=?", [e]))[0].n, 200);
  });
  test("🔴 una escritura en un engagement no frena a otro engagement", async () => {
    await sql("CREATE TRIGGER mapa_lento BEFORE INSERT ON target_ports FOR EACH ROW BEGIN IF NEW.port_number=4444 THEN DO SLEEP(2); END IF; END");
    try {
      const lenta = mapa(0, [{ objetivo: "10.10.200.1", puertos: [{ puerto: 4444 }] }]);
      await new Promise((ok) => setTimeout(ok, 300));
      const t = (await sql("SELECT id FROM engagement_targets WHERE engagement_id=? LIMIT 1", [E[1]]))[0].id, desde = Date.now();
      assert.equal((await panel("PUT", `/engagements/${E[1]}/targets/${t}`, { notes: "persona", jumped_from_id: null })).status, 200);
      assert.equal((await mapa(1, [{ objetivo: "10.11.200.1" }])).status, 200);
      assert.ok(Date.now() - desde < 1200, `${Date.now() - desde} ms`);
      assert.equal((await lenta).status, 200);
    } finally { await sql("DROP TRIGGER IF EXISTS mapa_lento"); }
  });
  test("🔴 agentes y personas sobre el mismo mapa: nadie recibe un error", async () => {
    const ids = (await sql("SELECT id FROM engagement_targets WHERE engagement_id=? LIMIT 40", [E[0]])).map((x) => x.id);
    const T = `/engagements/${E[0]}`;
    const r = await Promise.all([
      repetir(40, (n) => mapa(0, [...nuevos(0, n).map((e) => ({ ...e, notas: `a${n}`, puertos: [{ puerto: 22, servicio: "ssh" }, { puerto: 1000 + n }] })), { objetivo: `10.10.250.${n + 1}`, desde: `10.10.${n}.1` }])),
      repetir(60, (n) => mapa(0, Array.from({ length: 20 }, (_, k) => ({ objetivo: `10.10.${(n * 7 + k * 3) % 40}.${(k % 5) + 1}`, notas: `c${n}`, puertos: [{ puerto: 3000 + n, servicio: "x" }] })))),
      repetir(60, (n) => mapa(0, [{ objetivo: `10.10.${n % 40}.2`, desde: `10.10.${(n + 1) % 40}.3`, comprometido: true, puertos: [{ puerto: 2000 + n }] }])),
      repetir(150, (n) => panel("PUT", `${T}/targets/${ids[n % ids.length]}`, { notes: `persona ${n}`, os_type: "windows", jumped_from_id: ids[(n + 7) % ids.length] })),
      repetir(120, (n) => panel("POST", `${T}/targets`, { ip_address: `10.10.251.${n + 1}`, jumped_from_id: ids[n % ids.length] })),
      repetir(120, (n) => panel("PATCH", `${T}/targets/${ids[(n * 3) % ids.length]}/pivot`, { jumped_from_id: ids[(n * 5 + 1) % ids.length] })),
      repetir(20, () => panel("POST", `${T}/attack-map/sync-from-phases`, {})),
    ]);
    assert.deepEqual(malos(r), []);
  });
  test("🔴 lo que se borra mientras el agente escribe no da un error interno", async () => {
    await sql("CREATE TRIGGER mapa_lento BEFORE INSERT ON engagement_targets FOR EACH ROW BEGIN IF NEW.ip_address='10.10.252.1' THEN DO SLEEP(0.8); END IF; END");
    try {
      const id = (await sql("SELECT id FROM engagement_targets WHERE engagement_id=? AND ip_address='10.10.1.1'", [E[0]]))[0].id;
      const r = mapa(0, [{ objetivo: "10.10.252.1" }, { objetivo: "10.10.1.1", notas: "tarde", puertos: [{ puerto: 9 }] }]);
      await new Promise((ok) => setTimeout(ok, 300));
      assert.equal((await panel("DELETE", `/engagements/${E[0]}/targets/${id}`)).status, 200);
      assert.ok([200, 409].includes((await r).status), (await r).texto);
      assert.equal((await sql("SELECT COUNT(*) AS n FROM target_ports p LEFT JOIN engagement_targets t ON t.id=p.target_id WHERE t.id IS NULL"))[0].n, 0);
    } finally { await sql("DROP TRIGGER IF EXISTS mapa_lento"); }
  });
  test("🔴 una importación grande no frena los logs del mismo engagement", async () => {
    const puertos = Array.from({ length: 200000 }, (_, i) => `<port protocol="tcp" portid="${(i % 60000) + 1}"><state state="open"/></port>`).join("");
    const cuerpo = new FormData();
    cuerpo.append("formato", "nmap"); cuerpo.append("severidad_minima", "critical");
    cuerpo.append("archivo", new Blob([`<nmaprun><host><status state="up"/><address addr="10.12.1.1" addrtype="ipv4"/><ports>${puertos}</ports></host></nmaprun>`]), "s.xml");
    const t0 = Date.now();
    const imp = fetch(`${base}/api/agente/v1/engagements/${E[2]}/importar`, { method: "POST", headers: { Authorization: `Bearer ${keys[2]}` }, body: cuerpo }).then((r) => ({ status: r.status, ms: Date.now() - t0 }));
    let terminado = false, logs = 0;
    imp.then(() => { terminado = true; });
    while (!terminado) {
      const r = await pedir("POST", `/api/agente/v1/engagements/${E[2]}/logs`, keys[2], { fase: "scanning", notas: "x" });
      assert.equal(r.status, 201, r.texto);
      if (!terminado) logs++;
      await new Promise((ok) => setTimeout(ok, 20));
    }
    const r = await imp;
    assert.equal(r.status, 201);
    assert.ok(logs >= 4, `${logs} logs en ${r.ms} ms`);
  });
});
