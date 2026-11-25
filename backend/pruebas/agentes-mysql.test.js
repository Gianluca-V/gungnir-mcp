/**
 * Agentes de punta a punta: el server.js real contra un MySQL o MariaDB de verdad.
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
const fs = require("node:fs");
const net = require("node:net");
const path = require("node:path");
const jwt = require("jsonwebtoken");
const URL_DB = process.env.GUNGNIR_PRUEBA_DB;

const BACKEND = path.join(__dirname, "..");
const SECRETO = "pruebas-" + "0123456789abcdef".repeat(4);
const V1 = "/api/agente/v1";
const uid = () => crypto.randomUUID();

describe("agentes de punta a punta", { skip: !URL_DB && "sin GUNGNIR_PRUEBA_DB" }, () => {
  let pool, hijo, base, salida = "", correos = 0;
  const suf = crypto.randomBytes(4).toString("hex");
  const U = Object.fromEntries(["admin", "auditor", "pentester", "lector"].map((r) => [r, { id: uid(), role: r }]));
  const E = { a: uid(), b: uid(), cerrado: uid() };
  const CLIENTE = uid();
  const keys = {};

  const token = (r) => jwt.sign({ id: U[r].id, role: r, tv: 0 }, SECRETO);
  const sql = async (q, p) => (await pool.query(q, p))[0];
  async function pedir(metodo, ruta, { bearer, body, headers = {}, archivo, signal } = {}) {
    const h = { ...headers };
    if (bearer) h.Authorization = `Bearer ${bearer}`;
    let cuerpo;
    if (archivo) {
      cuerpo = new FormData();
      for (const [k, v] of Object.entries(body || {})) cuerpo.append(k, v);
      cuerpo.append("archivo", new Blob([archivo.contenido]), archivo.nombre);
    } else if (body !== undefined) { cuerpo = JSON.stringify(body); h["Content-Type"] = "application/json"; }
    const r = await fetch(base + ruta, { method: metodo, headers: h, body: cuerpo, signal });
    const texto = await r.text();
    let json = null; try { json = JSON.parse(texto); } catch {}
    return { status: r.status, texto, json, headers: r.headers };
  }
  const panel = (rol, metodo, ruta, body) => pedir(metodo, `/api/agentes${ruta}`, { bearer: token(rol), body });
  const ag = (key, metodo, ruta, body, extra) => pedir(metodo, V1 + ruta, { bearer: keys[key] || key, body, ...extra });
  async function nuevaKey(nombre, rol, nivel, engagements) {
    const r = await panel(rol, "POST", "/keys", { nombre, nivel_max: nivel, engagements });
    assert.equal(r.status, 201, r.texto);
    keys[nombre] = r.json.key; keys[`${nombre}_id`] = r.json.id;
  }
  const acceso = async (e, nivel, sensibles = false) => {
    const r = await panel("auditor", "PUT", `/engagements/${E[e]}`, { nivel_max: nivel, mostrar_sensibles: sensibles });
    assert.equal(r.status, 200, r.texto);
  };
  const contar = async (tabla, donde = "1=1", p = []) => Number((await sql(`SELECT COUNT(*) AS n FROM ${tabla} WHERE ${donde}`, p))[0].n);
  const hallazgo = (extra = {}) => ({ title: `SQLi ${uid()}`, affected_asset: "10.10.1.1:80/tcp", severity: "high", ...extra });

  before(async () => {
    const mysql = require("mysql2/promise");
    const u = new URL(URL_DB);
    // Un servidor de correo que acepta la conexión y nunca contesta.
    const smtp = await new Promise((ok) => { const s = net.createServer((c) => { correos++; c.on("error", () => {}).unref(); }); s.listen(0, "127.0.0.1", () => ok(s)); });
    smtp.unref();
    const puerto = await new Promise((ok) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => ok(p)); }); });
    hijo = spawn(process.execPath, ["server.js"], {
      cwd: BACKEND,
      env: { ...process.env, PORT: String(puerto), NODE_ENV: "test", JWT_SECRET: SECRETO, TRUST_PROXY: "false", VULN_FUENTES_EXTERNAS: "0", AGENTE_LIMITE_15MIN: "5000",
             SMTP_HOST: "127.0.0.1", SMTP_PORT: String(smtp.address().port), SMTP_SECURE: "false", SMTP_USER: "x", SMTP_PASS: "x",
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
    for (const x of Object.values(U))
      await sql("INSERT INTO users (id,username,email,password_hash,role) VALUES (?,?,?,?,?)", [x.id, `${x.role}-${suf}`, `${x.role}-${suf}@x`, "x", x.role]);
    await sql("INSERT INTO clients (id,name,contact_name,contact_phone) VALUES (?,?,?,?)", [CLIENTE, "Banco Ficticio", "Carla Gómez", "+54 11 5555-1234"]);
    for (const [k, id] of Object.entries(E))
      await sql("INSERT INTO engagements (id,client_id,title,status,notes,rules_of_engagement) VALUES (?,?,?,?,?,?)",
        [id, CLIENTE, `Pentest Banco Ficticio ${k}`, k === "cerrado" ? "delivered" : "in_progress", "VPN password=Sup3rClave9", "No tocar producción"]);
    for (const id of Object.values(E)) {
      for (const f of ["recon", "scanning", "exploitation"]) await sql("INSERT INTO phases (id,engagement_id,phase_type) VALUES (?,?,?)", [uid(), id, f]);
      for (const [t, v, d] of [["cidr", "10.10.0.0/16", 1], ["ip", "10.10.5.5", 0], ["domain", "app.ejemplo.com", 1]])
        await sql("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,?,?,?)", [uid(), id, t, v, d]);
    }
    await nuevaKey("total", "admin", "total", [E.a, E.cerrado]);
    await nuevaKey("escritura", "pentester", "escritura", [E.a]);
    await nuevaKey("propuesta", "pentester", "propuesta", [E.a]);
    await nuevaKey("lectura", "pentester", "lectura", [E.a]);
    await nuevaKey("delB", "admin", "total", [E.b]);
  });
  after(async () => {
    try {
    for (const f of pool ? await sql("SELECT filename FROM evidences WHERE engagement_id IN (?)", [Object.values(E)]) : [])
      fs.rmSync(path.join(BACKEND, "..", "uploads", f.filename), { force: true });
    if (pool) {
      await sql("DELETE FROM engagements WHERE client_id=?", [CLIENTE]);
      await sql("DELETE FROM clients WHERE id=?", [CLIENTE]);
      await sql("DELETE FROM users WHERE id IN (?)", [Object.values(U).map((x) => x.id)]);
    }
    } finally {
      if (pool) await pool.end();
      if (hijo && hijo.exitCode === null) await new Promise((ok) => { hijo.on("exit", ok); hijo.kill("SIGKILL"); });
    }
  });

  describe("acceso", () => {
    test("🔴 un engagement que nadie habilitó no da acceso, y responde igual que uno inexistente", async () => {
      const r = await ag("total", "GET", `/engagements/${E.a}`);
      const inexistente = await ag("total", "GET", `/engagements/${uid()}`);
      assert.equal(r.status, 404);
      assert.equal(r.texto, inexistente.texto);
      assert.deepEqual((await ag("total", "GET", "/engagements")).json.datos, []);
    });
    test("habilitado, la key ve solo lo suyo", async () => {
      await acceso("a", "total"); await acceso("b", "total"); await acceso("cerrado", "total");
      assert.equal((await ag("total", "GET", `/engagements/${E.a}`)).status, 200);
      assert.equal((await ag("total", "GET", `/engagements/${E.b}`)).status, 404);
      const l = await ag("lectura", "GET", "/engagements");
      assert.deepEqual(l.json.datos.map((x) => x.id), [E.a]);
      assert.equal(l.json.datos[0].nivel_efectivo, "lectura");
    });
    test("🔴 ninguna ruta de un engagement ajeno responde", async () => {
      const x = uid();
      const rutas = [["GET", ""], ["GET", "/alcance"], ["POST", "/alcance/verificar"], ["GET", "/hallazgos"], ["GET", `/hallazgos/${x}`], ["GET", "/propuestas"],
        ["GET", "/logs"], ["GET", "/evidencias"], ["GET", "/tecnicas"], ["GET", "/metodologia"], ["POST", "/logs"], ["POST", "/hallazgos"], ["PUT", `/hallazgos/${x}`],
        ["DELETE", `/hallazgos/${x}`], ["DELETE", `/logs/${x}`], ["POST", "/evidencias"], ["DELETE", `/evidencias/${x}`], ["POST", "/importar"],
        ["PUT", "/metodologia/WSTG-INFO-01"], ["POST", "/tecnicas"]];
      for (const [m, r] of rutas) assert.equal((await ag("total", m, `/engagements/${E.b}${r}`, m === "GET" ? undefined : {})).status, 404, `${m} ${r}`);
    });
    test("🔴 un hallazgo de otro engagement no se lee, modifica ni borra por el propio", async () => {
      const id = uid();
      await sql("INSERT INTO findings (id,engagement_id,title) VALUES (?,?,?)", [id, E.b, "ajeno"]);
      for (const [m, b] of [["GET"], ["PUT", { title: "pisado" }], ["DELETE"]])
        for (const e of [E.a, E.b]) assert.equal((await ag("total", m, `/engagements/${e}/hallazgos/${id}`, b)).status, 404);
      assert.equal((await sql("SELECT title FROM findings WHERE id=?", [id]))[0].title, "ajeno");
    });
    test("🔴 una key de agente no entra a ninguna ruta del panel", async () => {
      for (const [m, r] of [["GET", "/api/usuarios"], ["GET", "/api/settings"], ["GET", "/api/engagements"], ["GET", "/api/agentes/keys"], ["POST", "/api/agentes/keys"],
        ["POST", `/api/agentes/propuestas/${uid()}/aprobar`], ["PUT", `/api/agentes/engagements/${E.a}`], ["POST", `/api/engagements/${E.a}/scope`], ["POST", "/api/api-keys"]])
        assert.equal((await pedir(m, r, { bearer: keys.total, body: m === "GET" ? undefined : {} })).status, 401, r);
    });
    test("🔴 una sesión del panel no vale como key, ni una key mal formada", async () => {
      for (const b of [token("admin"), "gnga_x", "gnga_" + "0".repeat(64), "gngr_" + "0".repeat(64), undefined])
        assert.equal((await pedir("GET", `${V1}/yo`, { bearer: b })).status, 401);
    });
    test("revocada, vencida y usuario inactivo dejan de entrar con un error claro", async () => {
      await nuevaKey("temporal", "pentester", "lectura", [E.a]);
      const id = keys.temporal_id;
      assert.equal((await ag("temporal", "GET", "/yo")).status, 200);
      await sql("UPDATE agente_keys SET expira_en=NOW() - INTERVAL 1 SECOND WHERE id=?", [id]);
      let r = await ag("temporal", "GET", "/yo");
      assert.equal(r.status, 401); assert.match(r.json.error, /vencida/);
      await sql("UPDATE agente_keys SET expira_en=NOW() + INTERVAL 1 DAY WHERE id=?", [id]);
      await sql("UPDATE users SET is_active=0 WHERE id=?", [U.pentester.id]);
      const inactivo = await ag("temporal", "GET", "/yo");
      await sql("UPDATE users SET is_active=1 WHERE id=?", [U.pentester.id]);
      assert.equal(inactivo.status, 401);
      assert.equal((await panel("pentester", "DELETE", `/keys/${id}`)).status, 200);
      r = await ag("temporal", "GET", "/yo");
      assert.equal(r.status, 401); assert.match(r.json.error, /revocada/);
    });
    test("🔴 la key no se guarda en claro y no vuelve a mostrarse", async () => {
      assert.equal(await contar("agente_keys", "hash=?", [keys.total]), 0);
      const r = await panel("admin", "GET", "/keys");
      assert.ok(!r.texto.includes(keys.total) && !r.texto.includes(crypto.createHash("sha256").update(keys.total).digest("hex")));
    });
    test("🔴 nadie toca la key de otro, y un lector no crea keys que escriban", async () => {
      assert.equal((await panel("auditor", "DELETE", `/keys/${keys.lectura_id}`)).status, 404);
      assert.equal((await panel("auditor", "PATCH", `/keys/${keys.lectura_id}`, { nivel_max: "total" })).status, 404);
      assert.equal((await panel("lector", "POST", "/keys", { nombre: "x", nivel_max: "propuesta", engagements: [E.a] })).status, 403);
      assert.equal((await panel("lector", "POST", "/keys", { nombre: "x", engagements: [E.a] })).json.nivel_max, "lectura");
    });
    test("🔴 el pentester y el lector no cambian el acceso de un engagement", async () => {
      for (const r of ["pentester", "lector"]) assert.equal((await panel(r, "PUT", `/engagements/${E.a}`, { nivel_max: "total", mostrar_sensibles: true })).status, 403);
    });
    test("una key sin engagements, con días fuera de rango o un engagement inexistente se rechaza", async () => {
      for (const b of [{ engagements: [] }, { engagements: [uid()] }, { engagements: [E.a], dias: 9999 }, { engagements: [E.a], nivel_max: "ninguno" }, { engagements: "x" }, { engagements: [{ a: 1 }] }])
        assert.equal((await panel("admin", "POST", "/keys", { nombre: "x", ...b })).status, 400, JSON.stringify(b));
    });
    test("🔴 al bajar el rol del dueño, su key baja con él", async () => {
      await sql("UPDATE users SET role='lector' WHERE id=?", [U.pentester.id]);
      const r = await ag("escritura", "POST", `/engagements/${E.a}/logs`, { fase: "recon", notas: "x" });
      await sql("UPDATE users SET role='pentester' WHERE id=?", [U.pentester.id]);
      assert.equal(r.status, 403);
    });
    test("un engagement entregado queda en lectura aunque todo diga total", async () => {
      assert.equal((await ag("total", "GET", `/engagements/${E.cerrado}`)).json.nivel_efectivo, "lectura");
      assert.equal((await ag("total", "POST", `/engagements/${E.cerrado}/logs`, { fase: "recon", notas: "x" })).status, 403);
    });
  });

  describe("niveles", () => {
    const acciones = () => ({
      log: ["POST", `/engagements/${E.a}/logs`, { fase: "recon", notas: `nota ${uid()}` }],
      hallazgo: ["POST", `/engagements/${E.a}/hallazgos`, hallazgo()],
      metodologia: ["PUT", `/engagements/${E.a}/metodologia/WSTG-INFO-01`, { estado: "tested" }],
      tecnica: ["POST", `/engagements/${E.a}/tecnicas`, { nombre: `T ${uid()}`, fase: "recon" }],
      borrar: ["DELETE", `/engagements/${E.a}/hallazgos/${uid()}`],
    });
    const esperado = {
      lectura:   { log: 403, hallazgo: 403, metodologia: 403, tecnica: 403, borrar: 403 },
      propuesta: { log: 201, hallazgo: 202, metodologia: 403, tecnica: 403, borrar: 403 },
      escritura: { log: 201, hallazgo: 201, metodologia: 200, tecnica: 201, borrar: 403 },
      total:     { log: 201, hallazgo: 201, metodologia: 200, tecnica: 201, borrar: 404 },
    };
    for (const [nivel, e] of Object.entries(esperado))
      test(`${nivel}: ${JSON.stringify(e)}`, async () => {
        for (const [a, [m, r, b]] of Object.entries(acciones())) { const x = await ag(nivel, m, r, b); assert.equal(x.status, e[a], `${a}: ${x.texto}`); }
      });
    test("🔴 el tope del engagement gana sobre la key", async () => {
      await acceso("a", "lectura");
      const r = await ag("total", "POST", `/engagements/${E.a}/logs`, { fase: "recon", notas: "x" });
      await acceso("a", "total");
      assert.equal(r.status, 403); assert.equal(r.json.nivel_efectivo, "lectura");
    });
    test("borrar un hallazgo pide el mismo rol que en el panel", async () => {
      await nuevaKey("totalPentester", "pentester", "total", [E.a]);
      const id = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo())).json.hallazgo_id;
      assert.equal((await ag("totalPentester", "DELETE", `/engagements/${E.a}/hallazgos/${id}`)).status, 403);
      assert.equal((await ag("total", "DELETE", `/engagements/${E.a}/hallazgos/${id}`)).status, 200);
      assert.equal(await contar("findings", "id=?", [id]), 0);
    });
  });

  describe("alcance", () => {
    test("🔴 un log fuera de alcance se guarda marcado, avisa y queda como violación", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.a}/logs`, { fase: "scanning", objetivo: "8.8.8.8", comando: "nmap 8.8.8.8" });
      assert.equal(r.status, 201); assert.equal(r.json.fuera_de_alcance, true); assert.match(r.json.alerta, /VIOLACIÓN/);
      assert.equal((await sql("SELECT fuera_de_alcance FROM operation_logs WHERE id=?", [r.json.id]))[0].fuera_de_alcance, 1);
      const v = (await panel("auditor", "GET", "/violaciones")).json.find((x) => x.log_id === r.json.id);
      assert.equal(v.objetivo, "8.8.8.8"); assert.equal(v.command, "nmap 8.8.8.8");
      assert.ok((await panel("auditor", "GET", "/resumen")).json.violaciones >= 1);
      assert.equal((await ag("total", "DELETE", `/engagements/${E.a}/logs/${r.json.id}`)).status, 403);
      assert.equal((await panel("lector", "POST", `/violaciones/${v.id}/revisar`)).status, 403);
      assert.equal((await panel("auditor", "POST", `/violaciones/${v.id}/revisar`)).status, 200);
      assert.ok(!(await panel("auditor", "GET", "/violaciones")).json.some((x) => x.id === v.id));
    });
    test("🔴 un hallazgo fuera de alcance se rechaza, no se guarda y deja constancia", async () => {
      for (const k of ["propuesta", "total"]) {
        const h = hallazgo({ affected_asset: "10.10.5.5" });
        const antes = await contar("agente_violaciones", "engagement_id=? AND tipo='hallazgo'", [E.a]);
        const r = await ag(k, "POST", `/engagements/${E.a}/hallazgos`, h);
        assert.equal(r.status, 422, r.texto);
        assert.equal(await contar("findings", "title=?", [h.title]), 0);
        assert.equal(await contar("agente_violaciones", "engagement_id=? AND tipo='hallazgo'", [E.a]), antes + 1);
      }
    });
    test("🔴 no se mueve un hallazgo a un activo fuera de alcance al modificarlo", async () => {
      const id = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo())).json.hallazgo_id;
      assert.equal((await ag("escritura", "PUT", `/engagements/${E.a}/hallazgos/${id}`, { affected_asset: "8.8.4.4" })).status, 422);
    });
    test("un comando sin objetivo no entra", async () => {
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.a}/logs`, { fase: "recon", comando: "nmap" })).status, 400);
    });
    test("verificar dice cuáles están dentro y por qué no", async () => {
      const r = await ag("lectura", "POST", `/engagements/${E.a}/alcance/verificar`, { objetivos: ["10.10.1.1", "app.ejemplo.com", "ejemplo.com"] });
      assert.deepEqual(r.json.datos.map((d) => d.dentro), [true, true, false]);
      assert.equal(r.json.todos_dentro, false);
    });
  });

  describe("hallazgos de la verificación independiente", () => {
    const conAlcance = async (items, fn) => {
      const antes = await sql("SELECT * FROM scope_items WHERE engagement_id=?", [E.a]);
      await sql("DELETE FROM scope_items WHERE engagement_id=?", [E.a]);
      for (const [t, v, d] of items) await sql("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,?,?,?)", [uid(), E.a, t, v, d]);
      try { return await fn(); } finally {
        await sql("DELETE FROM scope_items WHERE engagement_id=?", [E.a]);
        for (const a of antes) await sql("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,?,?,?)", [a.id, E.a, a.type, a.value, a.in_scope]);
      }
    };
    const nmap = (ip, puerto, nombre) => `<nmaprun><host><status state="up"/><address addr="${ip}" addrtype="ipv4"/>${nombre ? `<hostnames><hostname name="${nombre}" type="user"/></hostnames>` : ""}<ports><port protocol="tcp" portid="${puerto}"><state state="open"/></port></ports></host></nmaprun>`;
    const importar = (key, formato, contenido) => ag(key, "POST", `/engagements/${E.a}/importar`, { formato }, { archivo: { nombre: formato === "nuclei" ? "n.jsonl" : "s.xml", contenido } });

    test("🔴 importar guarda el activo que está en alcance, no otro", () => conAlcance([["domain", "web.acme.com", 1]], async () => {
      const r = await importar("propuesta", "nmap", nmap("203.0.113.9", 80, "web.acme.com"));
      assert.equal(r.status, 201, r.texto);
      const p = r.json.muestra[0];
      assert.equal(p.affected_asset, "web.acme.com:80/tcp");
      assert.equal((await panel("auditor", "POST", `/propuestas/${p.id}/aprobar`)).status, 200);
    }));
    test("🔴 importar respeta exclusiones por puerto y por ruta, y el alcance por puerto", async () => {
      await conAlcance([["cidr", "10.20.0.0/24", 1], ["ip", "10.20.0.5:22", 0]], async () => {
        assert.equal((await importar("escritura", "nmap", nmap("10.20.0.5", 22))).json.hallazgos_creados, 0);
        assert.equal((await importar("escritura", "nmap", nmap("10.20.0.5", 80))).json.hallazgos_creados, 1);
      });
      const nuclei = (u) => JSON.stringify({ "template-id": "t", info: { name: `N ${uid()}`, severity: "high" }, host: "https://web.acme.com", "matched-at": u, type: "http" });
      await conAlcance([["domain", "web.acme.com", 1], ["url", "https://web.acme.com/admin", 0]], async () => {
        assert.equal((await importar("escritura", "nuclei", nuclei("https://web.acme.com/admin/login"))).json.hallazgos_creados, 0);
        const r = await importar("escritura", "nuclei", nuclei("https://web.acme.com/blog"));
        assert.equal(r.json.muestra[0].affected_asset, "https://web.acme.com/blog");
      });
      await conAlcance([["url", "https://web.acme.com/portal", 1]], async () =>
        assert.equal((await importar("escritura", "nuclei", nuclei("https://web.acme.com/portal/x"))).json.hallazgos_creados, 1));
      await conAlcance([["ip", "10.20.0.7:443", 1]], async () => assert.equal((await importar("escritura", "nmap", nmap("10.20.0.7", 443))).json.hallazgos_creados, 1));
    });
    test("🔴 muchos equipos fuera de alcance se resumen en pocas violaciones", async () => {
      const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
      const xml = `<nmaprun>${Array.from({ length: 1500 }, (_, i) => nmap(`172.20.${i >> 8}.${i & 255}`, 80).replace(/<\/?nmaprun>/g, "")).join("")}${nmap("10.10.4.4", 80).replace(/<\/?nmaprun>/g, "")}</nmaprun>`;
      const r = await importar("propuesta", "nmap", xml);
      assert.equal(r.status, 201, r.texto);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 51);
    });
    test("🔴 el listado oculta lo mismo que el detalle, y los motivos también se ocultan", async () => {
      await sql("UPDATE engagements SET title='Pentest - Carla Gómez' WHERE id=?", [E.a]);
      const lista = await ag("lectura", "GET", "/engagements");
      await sql("UPDATE engagements SET title='Pentest Banco Ficticio a' WHERE id=?", [E.a]);
      assert.ok(!lista.texto.includes("Carla"));
      await conAlcance([["cidr", "10.10.0.0/16", 1], ["url", "https://admin:Secreta123@vpn-{a}.acme.com/", 0]], async () => {
        const v = await ag("lectura", "POST", `/engagements/${E.a}/alcance/verificar`, { objetivos: ["10.10.1.1"] });
        assert.ok(!v.texto.includes("Secreta123"), v.texto); assert.equal(v.json.contenido_no_confiable, true);
        for (const [r, b] of [["logs", { fase: "recon", objetivo: "10.10.1.1", comando: "x" }], ["hallazgos", hallazgo()]])
          assert.ok(!(await ag("propuesta", "POST", `/engagements/${E.a}/${r}`, b)).texto.includes("Secreta123"), r);
      });
    });
    test("🔴 marcar la metodología sin nota no borra la que había", async () => {
      const r = `/engagements/${E.a}/metodologia/WSTG-INFO-05`;
      await ag("escritura", "PUT", r, { estado: "pending", nota: "nota humana" });
      await ag("escritura", "PUT", r, { estado: "tested" });
      const f = (await sql("SELECT status,note FROM methodology_checks WHERE engagement_id=? AND item_key='WSTG-INFO-05'", [E.a]))[0];
      assert.deepEqual({ ...f }, { status: "tested", note: "nota humana" });
    });
    test("🔴 hallazgos iguales a la vez, con claves distintas, crean uno solo", async () => {
      const h = hallazgo();
      const r = await Promise.all(Array.from({ length: 8 }, () => ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, h, { headers: { "Idempotency-Key": uid() } })));
      assert.equal(r.filter((x) => x.status === 201).length, 1);
      assert.equal(await contar("findings", "title=?", [h.title]), 1);
    });
    test("🔴 aprobar algo que ya existe como hallazgo se avisa y no duplica", async () => {
      const h = hallazgo(), id = (await ag("propuesta", "POST", `/engagements/${E.a}/hallazgos`, h)).json.propuesta_id;
      await sql("INSERT INTO findings (id,engagement_id,title,affected_asset) VALUES (?,?,?,?)", [uid(), E.a, h.title, h.affected_asset]);
      assert.equal((await panel("auditor", "POST", `/propuestas/${id}/aprobar`)).status, 409);
      assert.equal(await contar("findings", "title=?", [h.title]), 1);
    });
    test("🔴 un agente no revierte un riesgo aceptado por una persona", async () => {
      const id = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo())).json.hallazgo_id;
      await sql("UPDATE findings SET status='accepted' WHERE id=?", [id]);
      assert.equal((await ag("escritura", "PUT", `/engagements/${E.a}/hallazgos/${id}`, { status: "open" })).status, 409);
      assert.equal((await sql("SELECT status FROM findings WHERE id=?", [id]))[0].status, "accepted");
    });
    test("🔴 cambiar una parte del acceso no pisa la otra", async () => {
      await acceso("a", "total", true);
      try {
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "lectura" })).status, 200);
        assert.deepEqual({ ...(await sql("SELECT nivel_max, mostrar_sensibles FROM agente_engagements WHERE engagement_id=?", [E.a]))[0] }, { nivel_max: "lectura", mostrar_sensibles: 1 });
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { mostrar_sensibles: false })).status, 200);
        assert.equal((await sql("SELECT nivel_max FROM agente_engagements WHERE engagement_id=?", [E.a]))[0].nivel_max, "lectura");
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, {})).status, 400);
      } finally { await acceso("a", "total", false); }
    });
    test("🔴 quitar el acceso vuelve a ocultar los datos", async () => {
      await acceso("a", "total", true);
      try {
        await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "ninguno" });
        assert.equal((await sql("SELECT mostrar_sensibles FROM agente_engagements WHERE engagement_id=?", [E.a]))[0].mostrar_sensibles, 0);
      } finally { await acceso("a", "total", false); }
    });
    test("🔴 sin acceso no se pueden mostrar datos sensibles: ni a la vez ni antes de habilitarlo", async () => {
      try {
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "ninguno", mostrar_sensibles: true })).status, 400);
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "ninguno" })).status, 200);
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { mostrar_sensibles: true })).status, 409);
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "lectura" })).status, 200);
        assert.equal((await sql("SELECT mostrar_sensibles FROM agente_engagements WHERE engagement_id=?", [E.a]))[0].mostrar_sensibles, 0);
        await sql("DELETE FROM agente_engagements WHERE engagement_id=?", [E.a]);
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { mostrar_sensibles: true })).status, 409);
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "lectura", mostrar_sensibles: true })).status, 200);
      } finally { await acceso("a", "total", false); }
    });
    test("🔴 un servidor de correo que no contesta no demora el alta de un hallazgo", async () => {
      const aviso = JSON.stringify({ email_enabled: true, email_to: "x@example.com", min_severity: "high" });
      await sql("INSERT INTO settings (`key`,`value`) VALUES ('notificaciones',?) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)", [aviso]);
      const antes = correos;
      try {
        const r = await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ severity: "critical" }), { signal: AbortSignal.timeout(4000) });
        assert.equal(r.status, 201, r.texto);
        for (let i = 0; i < 40 && correos === antes; i++) await new Promise((ok) => setTimeout(ok, 50));
        assert.equal(correos, antes + 1, "el aviso se intenta igual");
      } finally { await sql("DELETE FROM settings WHERE `key`='notificaciones'"); }
    });
    test("🔴 el tope de lectura cuenta lo que pasa la severidad mínima, y al superarlo también deja constancia", async () => {
      // 23 es de severidad alta para el lector de nmap; los puertos 30000 y siguientes, informativos.
      const puertos = (ip, desde, n) => `<host><status state="up"/><address addr="${ip}" addrtype="ipv4"/><ports>${Array.from({ length: n }, (_, i) => `<port protocol="tcp" portid="${desde + i}"><state state="open"/></port>`).join("")}</ports></host>`;
      const grande = `<nmaprun>${puertos("10.10.8.1", 23, 1)}${puertos("10.10.8.1", 30000, 20100)}${puertos("8.8.4.9", 30000, 1)}</nmaprun>`;
      const subir = (severidad_minima) => ag("escritura", "POST", `/engagements/${E.a}/importar`, { formato: "nmap", severidad_minima }, { archivo: { nombre: "s.xml", contenido: grande } });
      const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
      const r = await subir("high");
      assert.equal(r.status, 201, r.texto);
      assert.equal(r.json.hallazgos_creados, 1);
      assert.equal(r.json.leidos, 20102);
      assert.equal(r.json.bajo_severidad_minima, 20100);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 1);
      assert.equal((await subir("info")).status, 413);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 2);
    });
    test("🔴 en lote, un error inesperado no frena al resto", async () => {
      const ids = [];
      for (const t of ["rompe", "sigue"]) ids.push((await ag("propuesta", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ title: `${t} ${uid()}` }))).json.propuesta_id);
      let r;
      await sql("CREATE TRIGGER falla_lote BEFORE INSERT ON findings FOR EACH ROW BEGIN IF NEW.title LIKE 'rompe%' THEN SIGNAL SQLSTATE '45000'; END IF; END");
      try { r = await panel("auditor", "POST", "/propuestas/aprobar-lote", { ids }); } finally { await sql("DROP TRIGGER IF EXISTS falla_lote"); }
      assert.equal(r.status, 200, r.texto);
      assert.deepEqual(r.json.aprobadas, [ids[1]]); assert.equal(r.json.errores[0].id, ids[0]);
    });
    test("🔴 un XML se guarda como texto: abierto en el navegador no ejecuta nada", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.a}/evidencias`, {}, { archivo: { nombre: "x.xml", contenido: "<html xmlns='http://www.w3.org/1999/xhtml'/>" } });
      assert.equal((await sql("SELECT file_type FROM evidences WHERE id=?", [r.json.evidencia_id]))[0].file_type, "text/plain");
    });
    test("🔴 técnicas iguales a la vez crean una sola", async () => {
      const nombre = `T ${uid()}`;
      const r = await Promise.all(Array.from({ length: 6 }, () => ag("escritura", "POST", `/engagements/${E.a}/tecnicas`, { nombre, fase: "recon" })));
      assert.equal(r.filter((x) => x.status === 201).length, 1);
    });
    test("🔴 una importación rechazada por grande igual deja constancia de lo que estaba fuera", async () => {
      const uno = (ip, p) => nmap(ip, p).replace(/<\/?nmaprun>/g, "");
      const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
      const r = await importar("escritura", "nmap", `<nmaprun>${uno("8.8.4.4", 53)}${Array.from({ length: 301 }, (_, i) => uno(`10.10.6.${i % 250}`, 2000 + i)).join("")}</nmaprun>`);
      assert.equal(r.status, 413);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 1);
    });
    test("un dato guardado que no es JSON no rompe el arsenal", async () => {
      const id = uid();
      await sql("INSERT INTO arsenal_commands (id,tool_key,title,command,tags) VALUES (?,?,?,?,?)", [id, "propia", `Propio ${suf}`, "x", JSON.stringify("a,b")]);
      const r = await ag("lectura", "GET", `/arsenal?q=${suf}`);
      await sql("DELETE FROM arsenal_commands WHERE id=?", [id]);
      assert.equal(r.status, 200, r.texto); assert.equal(r.json.datos.length, 1);
    });
    test("🔴 las keys inválidas no bloquean a las válidas, ni muchas válidas a la vez", async () => {
      const malas = await Promise.all(Array.from({ length: 90 }, () => pedir("GET", `${V1}/yo`, { bearer: "gnga_" + "1".repeat(64) })));
      assert.ok(malas.some((x) => x.status === 429));
      const buenas = await Promise.all(Array.from({ length: 120 }, () => ag("lectura", "GET", "/yo")));
      assert.ok(buenas.every((x) => x.status === 200), [...new Set(buenas.map((x) => x.status))].join());
    });
  });

  describe("ocultamiento", () => {
    test("🔴 ni el cliente ni los secretos salen mientras no se habilite", async () => {
      const r = await ag("lectura", "GET", `/engagements/${E.a}`);
      for (const s of ["Banco Ficticio", "Sup3rClave9", "Carla"]) assert.ok(!r.texto.includes(s), s);
      assert.equal(r.json.datos_ocultos, true);
      assert.ok(!(await ag("lectura", "GET", "/engagements")).texto.includes("Banco Ficticio"));
    });
    test("habilitado por engagement, salen", async () => {
      await acceso("a", "total", true);
      const r = await ag("lectura", "GET", `/engagements/${E.a}`);
      await acceso("a", "total", false);
      assert.ok(r.texto.includes("Banco Ficticio") && r.texto.includes("Sup3rClave9"));
    });
    test("🔴 guardar una marca o un recorte se rechaza: pisaría el dato real", async () => {
      const id = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ description: "password=Real12345" }))).json.hallazgo_id;
      const leido = (await ag("escritura", "GET", `/engagements/${E.a}/hallazgos/${id}`)).json.datos.description;
      assert.match(leido, /\[OCULTO:/);
      assert.equal((await ag("escritura", "PUT", `/engagements/${E.a}/hallazgos/${id}`, { description: leido })).status, 400);
      assert.equal((await ag("escritura", "PUT", `/engagements/${E.a}/hallazgos/${id}`, { description: "x\n[RECORTADO: faltan 9 caracteres]" })).status, 400);
      assert.equal((await sql("SELECT description FROM findings WHERE id=?", [id]))[0].description, "password=Real12345");
    });
    test("una evidencia se lista, pero su contenido no sale", async () => {
      await ag("propuesta", "POST", `/engagements/${E.a}/evidencias`, {}, { archivo: { nombre: "salida.txt", contenido: "SECRETO-EVIDENCIA" } });
      const r = await ag("lectura", "GET", `/engagements/${E.a}/evidencias`);
      assert.ok(r.texto.includes("salida.txt") && !r.texto.includes("SECRETO-EVIDENCIA"));
    });
    test("un texto largo sale recortado y completo=1 trae más", async () => {
      const id = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ description: "x ".repeat(5000) }))).json.hallazgo_id;
      assert.match((await ag("lectura", "GET", `/engagements/${E.a}/hallazgos/${id}`)).json.datos.description, /RECORTADO/);
      assert.ok(!(await ag("lectura", "GET", `/engagements/${E.a}/hallazgos/${id}?completo=1`)).json.datos.description.includes("RECORTADO"));
    });
  });

  describe("propuestas", () => {
    const proponer = async (h = hallazgo()) => ({ h, id: (await ag("propuesta", "POST", `/engagements/${E.a}/hallazgos`, h)).json.propuesta_id });
    test("🔴 una propuesta no es un hallazgo hasta que una persona la aprueba", async () => {
      const { h, id } = await proponer(hallazgo({ references_list: ["https://x"], cvss_score_31: 9.8 }));
      assert.equal(await contar("findings", "title=?", [h.title]), 0);
      assert.equal((await panel("lector", "POST", `/propuestas/${id}/aprobar`)).status, 403);
      const r = await panel("auditor", "POST", `/propuestas/${id}/aprobar`);
      assert.equal(r.status, 200, r.texto);
      const f = (await sql("SELECT * FROM findings WHERE id=?", [r.json.finding_id]))[0];
      assert.equal(f.title, h.title); assert.equal(f.severity, "high"); assert.equal(f.initial_severity, "high"); assert.equal(Number(f.cvss_score_31), 9.8);
      assert.equal(f.created_by, U.auditor.id);
      assert.equal((await panel("auditor", "POST", `/propuestas/${id}/aprobar`)).status, 409);
      assert.equal(await contar("findings", "title=?", [h.title]), 1);
    });
    test("aprobar dos veces a la vez crea un solo hallazgo", async () => {
      const { h, id } = await proponer();
      // La fila tomada desde afuera junta a todos en el mismo punto antes de que lean el estado.
      const con = await pool.getConnection();
      await con.beginTransaction();
      await con.query("SELECT id FROM engagements WHERE id=? FOR UPDATE", [E.a]);
      const todos = Promise.all([1, 2, 3, 4].map(() => panel("auditor", "POST", `/propuestas/${id}/aprobar`)));
      await new Promise((ok) => setTimeout(ok, 800));
      await con.commit(); con.release();
      const r = await todos;
      assert.deepEqual(r.map((x) => x.status).sort(), [200, 409, 409, 409]);
      assert.equal(await contar("findings", "title=?", [h.title]), 1);
    });
    test("rechazada, no se puede aprobar y el agente ve el motivo", async () => {
      const { id } = await proponer();
      assert.equal((await panel("auditor", "POST", `/propuestas/${id}/rechazar`, { motivo: "Falso positivo" })).status, 200);
      assert.equal((await panel("auditor", "POST", `/propuestas/${id}/aprobar`)).status, 409);
      const r = await ag("propuesta", "GET", `/engagements/${E.a}/propuestas?estado=rechazada`);
      assert.equal(r.json.datos.find((x) => x.id === id).motivo, "Falso positivo");
    });
    test("una key no ve las propuestas de otra", async () => {
      const { id } = await proponer();
      assert.ok(!(await ag("total", "GET", `/engagements/${E.a}/propuestas`)).texto.includes(id));
    });
    test("una modificación propuesta avisa si el hallazgo cambió en el medio", async () => {
      const fid = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo())).json.hallazgo_id;
      const r = await ag("propuesta", "PUT", `/engagements/${E.a}/hallazgos/${fid}`, { severity: "low" });
      assert.equal(r.status, 202);
      await sql("UPDATE findings SET updated_at=NOW() + INTERVAL 5 SECOND, title='editado' WHERE id=?", [fid]);
      const c = await panel("auditor", "POST", `/propuestas/${r.json.propuesta_id}/aprobar`);
      assert.equal(c.status, 409); assert.equal(c.json.conflicto, true);
      assert.equal((await panel("auditor", "POST", `/propuestas/${r.json.propuesta_id}/aprobar`, { forzar: true })).status, 200);
      const f = (await sql("SELECT severity,title FROM findings WHERE id=?", [fid]))[0];
      assert.deepEqual({ ...f }, { severity: "low", title: "editado" });
    });
    test("🔴 si el activo salió del alcance, no se aprueba", async () => {
      const { id } = await proponer(hallazgo({ affected_asset: "app.ejemplo.com" }));
      await sql("UPDATE scope_items SET in_scope=0 WHERE engagement_id=? AND value='app.ejemplo.com'", [E.a]);
      const r = await panel("auditor", "POST", `/propuestas/${id}/aprobar`);
      await sql("UPDATE scope_items SET in_scope=1 WHERE engagement_id=? AND value='app.ejemplo.com'", [E.a]);
      assert.equal(r.status, 409);
    });
    test("en lote, una con problemas no frena al resto", async () => {
      const a = await proponer(), b = await proponer();
      await panel("auditor", "POST", `/propuestas/${a.id}/rechazar`);
      const r = await panel("auditor", "POST", "/propuestas/aprobar-lote", { ids: [a.id, b.id, uid()] });
      assert.deepEqual(r.json.aprobadas, [b.id]); assert.equal(r.json.errores.length, 2);
    });
  });

  describe("reintentos", () => {
    const clave = (k) => ({ headers: { "Idempotency-Key": k } });
    test("🔴 el mismo pedido repetido escribe una sola vez", async () => {
      const b = { fase: "recon", objetivo: "10.10.1.1", comando: `id ${uid()}` }, k = clave(uid());
      const a = await ag("propuesta", "POST", `/engagements/${E.a}/logs`, b, k), c = await ag("propuesta", "POST", `/engagements/${E.a}/logs`, b, k);
      assert.equal(a.json.id, c.json.id); assert.equal(c.headers.get("idempotency-replayed"), "true");
      assert.equal(await contar("operation_logs", "command=?", [b.comando]), 1);
    });
    test("🔴 a la vez, también", async () => {
      const b = { fase: "recon", objetivo: "10.10.1.1", comando: `id ${uid()}` }, k = clave(uid());
      const r = await Promise.all(Array.from({ length: 25 }, () => ag("propuesta", "POST", `/engagements/${E.a}/logs`, b, k)));
      assert.ok(r.every((x) => [201, 409].includes(x.status)), r.map((x) => x.status).join());
      assert.equal(await contar("operation_logs", "command=?", [b.comando]), 1);
    });
    test("muchos pedidos fuera de alcance a la vez no traban el pool", async () => {
      const r = await Promise.all(Array.from({ length: 40 }, () => ag("propuesta", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ affected_asset: "9.9.9.9" }))));
      assert.ok(r.every((x) => x.status === 422));
    });
    test("la misma clave con otro contenido se rechaza, y otra key puede usar la misma", async () => {
      const k = clave(uid()), b = { fase: "recon", notas: "uno" };
      await ag("propuesta", "POST", `/engagements/${E.a}/logs`, b, k);
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.a}/logs`, { ...b, notas: "dos" }, k)).status, 422);
      assert.equal((await ag("escritura", "POST", `/engagements/${E.a}/logs`, b, k)).status, 201);
    });
    test("un pedido que falló se puede reintentar con la misma clave", async () => {
      const k = clave(uid()), h = hallazgo({ affected_asset: "app.ejemplo.com" });
      await sql("UPDATE scope_items SET in_scope=0 WHERE engagement_id=? AND value='app.ejemplo.com'", [E.a]);
      assert.equal((await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, h, k)).status, 422);
      await sql("UPDATE scope_items SET in_scope=1 WHERE engagement_id=? AND value='app.ejemplo.com'", [E.a]);
      assert.equal((await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, h, k)).status, 201);
    });
    test("un hallazgo igual a uno abierto se rechaza y dice cuál es", async () => {
      const h = hallazgo();
      const a = await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, h), b = await ag("propuesta", "POST", `/engagements/${E.a}/hallazgos`, h);
      assert.equal(b.status, 409); assert.equal(b.json.existente.id, a.json.hallazgo_id);
    });
  });

  describe("entrada hostil", () => {
    test("🔴 tipos inesperados dan 400 y nunca 500", async () => {
      const malos = [{ title: { a: 1 } }, { title: ["x"] }, { title: "x".repeat(501) }, { severity: "urgente" }, { severity: null }, { cvss_score_31: "9" }, { cvss_score_31: 11 },
        { references_list: "x" }, { references_list: [1] }, { status: "accepted" }, { created_by: "x" }, { engagement_id: E.b }, { id: "x" }, { affected_asset: null }];
      for (const m of malos) { const r = await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo(m)); assert.equal(r.status, 400, JSON.stringify(m) + r.texto); }
      for (const b of [[], "x", null, 5]) assert.ok([400].includes((await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, b)).status));
      for (const q of ["limite=0", "limite=x", "limite=1;drop", "desde=-1", "severidad=x", "limite=1&limite=2", "severidad[a]=1"])
        assert.equal((await ag("lectura", "GET", `/engagements/${E.a}/hallazgos?${q}`)).status, 400, q);
    });
    test("🔴 los nombres de archivo no escapan de la carpeta y lo ejecutable no entra", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.a}/evidencias`, {}, { archivo: { nombre: "../../../server.txt", contenido: "x" } });
      assert.equal(r.status, 201); assert.equal(r.json.nombre, "server.txt");
      const f = (await sql("SELECT filename FROM evidences WHERE id=?", [r.json.evidencia_id]))[0].filename;
      assert.match(f, /^[0-9a-f]{32}$/);
      for (const nombre of ["x.html", "x.svg", "x.php", "x.exe", "x", "x.txt.js"])
        assert.equal((await ag("propuesta", "POST", `/engagements/${E.a}/evidencias`, {}, { archivo: { nombre, contenido: "x" } })).status, 400, nombre);
    });
    test("una subida rechazada no deja el archivo en disco", async () => {
      const dir = path.join(BACKEND, "..", "uploads"), antes = fs.readdirSync(dir).length;
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.a}/evidencias`, { hallazgo_id: uid() }, { archivo: { nombre: "a.txt", contenido: "x" } })).status, 404);
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.a}/importar`, { formato: "nmap" }, { archivo: { nombre: "a.xml", contenido: "<nada/>" } })).status, 400);
      assert.equal(fs.readdirSync(dir).length, antes);
    });
    test("si la escritura falla después de guardar el archivo, el archivo se borra", async () => {
      const dir = path.join(BACKEND, "..", "uploads"), antes = fs.readdirSync(dir).length, evs = await contar("evidences", "engagement_id=?", [E.a]);
      await sql("CREATE TRIGGER falla_prueba BEFORE INSERT ON findings FOR EACH ROW SIGNAL SQLSTATE '45000'");
      const xml = `<nmaprun><host><status state="up"/><address addr="10.10.8.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>`;
      let r;
      try { r = await ag("escritura", "POST", `/engagements/${E.a}/importar`, { formato: "nmap" }, { archivo: { nombre: "a.xml", contenido: xml } }); }
      finally { await sql("DROP TRIGGER IF EXISTS falla_prueba"); }
      assert.equal(r.status, 500);
      await new Promise((ok) => setTimeout(ok, 200));
      assert.equal(fs.readdirSync(dir).length, antes);
      assert.equal(await contar("evidences", "engagement_id=?", [E.a]), evs);
    });
    test("una subida demasiado grande responde 413", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.a}/evidencias`, {}, { archivo: { nombre: "a.txt", contenido: Buffer.alloc(21 * 1024 * 1024) } });
      assert.equal(r.status, 413);
    });
  });

  describe("importación", () => {
    const host = (ip, puerto, servicio = "http") => `<host><status state="up"/><address addr="${ip}" addrtype="ipv4"/><ports><port protocol="tcp" portid="${puerto}"><state state="open"/><service name="${servicio}"/></port></ports></host>`;
    const xml = (...h) => `<?xml version="1.0"?><nmaprun>${h.join("")}</nmaprun>`;
    const importar = (key, contenido, body = {}, extra = {}) => ag(key, "POST", `/engagements/${E.a}/importar`, { formato: "nmap", ...body }, { archivo: { nombre: "scan.xml", contenido }, ...extra });
    test("🔴 entra lo que está en alcance, se ignora y se denuncia el resto, y el original queda como evidencia", async () => {
      const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
      const r = await importar("escritura", xml(host("10.10.2.1", 445), host("10.10.5.5", 80), host("8.8.8.8", 53)));
      assert.equal(r.status, 201, r.texto);
      assert.equal(r.json.hallazgos_creados, 1);
      assert.deepEqual(r.json.hosts_fuera_de_alcance.sort(), ["10.10.5.5", "8.8.8.8"]);
      assert.equal(await contar("findings", "engagement_id=? AND affected_asset LIKE '8.8.8.8%'", [E.a]), 0);
      assert.equal(await contar("findings", "engagement_id=? AND affected_asset='10.10.2.1:445/tcp'", [E.a]), 1);
      assert.equal(await contar("evidences", "id=?", [r.json.evidencia_id]), 1);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 2);
    });
    test("repetida, no duplica; con otra severidad mínima, filtra", async () => {
      assert.equal((await importar("escritura", xml(host("10.10.2.1", 445)))).json.duplicados, 1);
      const r = await importar("escritura", xml(host("10.10.2.2", 8080)), { severidad_minima: "high" });
      assert.equal(r.json.hallazgos_creados, 0); assert.equal(r.json.bajo_severidad_minima, 1);
    });
    test("en propuesta crea propuestas", async () => {
      const r = await importar("propuesta", xml(host("10.10.2.9", 3389)));
      assert.equal(r.json.propuestas_creadas, 1);
      assert.equal(await contar("findings", "affected_asset='10.10.2.9:3389/tcp'"), 0);
    });
    test("demasiados resultados se rechazan enteros y un formato equivocado da 400", async () => {
      const r = await importar("escritura", xml(...Array.from({ length: 301 }, (_, i) => host(`10.10.7.${i % 250}`, 1000 + i))));
      assert.equal(r.status, 413);
      assert.equal(await contar("findings", "affected_asset LIKE '10.10.7.%'"), 0);
      assert.equal((await importar("escritura", "basura")).status, 400);
      assert.equal((await importar("escritura", xml(host("10.10.2.1", 1)), { formato: "sarif" })).status, 400);
    });
    test("reintentada con la misma clave no duplica la evidencia", async () => {
      const k = { headers: { "Idempotency-Key": uid() } }, c = xml(host("10.10.3.3", 21));
      const a = await importar("escritura", c, {}, k), b = await importar("escritura", c, {}, k);
      assert.equal(a.status, 201, a.texto);
      assert.equal(a.json.evidencia_id, b.json.evidencia_id);
      assert.equal(b.headers.get("idempotency-replayed"), "true");
      assert.equal(await contar("evidences", "id=?", [a.json.evidencia_id]), 1);
    });
  });

  describe("consultas y referencia", () => {
    test("la paginación avanza y avisa si hay más", async () => {
      const a = (await ag("lectura", "GET", `/engagements/${E.a}/hallazgos?limite=2`)).json;
      assert.equal(a.datos.length, 2); assert.equal(a.hay_mas, true);
      const b = (await ag("lectura", "GET", `/engagements/${E.a}/hallazgos?limite=2&desde=${a.siguiente}`)).json;
      assert.ok(!a.datos.some((x) => b.datos.some((y) => y.id === x.id)));
      assert.equal(a.contenido_no_confiable, true);
    });
    test("el arsenal busca, respeta lo oculto en el panel y suma lo propio", async () => {
      const r = await ag("lectura", "GET", "/arsenal?q=SYN&herramienta=nmap");
      assert.equal(r.json.datos[0].id, "nmap-syn");
      await sql("INSERT INTO cmd_overrides (item_id,hidden) VALUES ('nmap-syn',1)");
      const o = await ag("lectura", "GET", "/arsenal?q=SYN&herramienta=nmap");
      await sql("DELETE FROM cmd_overrides WHERE item_id='nmap-syn'");
      assert.ok(!o.json.datos.some((x) => x.id === "nmap-syn"));
    });
    test("plantillas, metodología y logs responden", async () => {
      assert.equal((await ag("lectura", "GET", "/plantillas?q=sql")).status, 200);
      assert.equal((await ag("lectura", "GET", `/engagements/${E.a}/metodologia?estado=pending&limite=3`)).json.datos.length, 3);
      assert.ok((await ag("lectura", "GET", `/engagements/${E.a}/logs?fase=recon`)).json.datos.length > 0);
      assert.equal((await ag("lectura", "GET", "/cve/nada")).status, 400);
      assert.equal((await ag("lectura", "GET", "/inexistente")).status, 404);
    });
    test("lo que hizo el agente queda en la auditoría con su key", async () => {
      assert.ok(await contar("audit_logs", "user_id=? AND action LIKE 'agente_%' AND detail LIKE '[key escritura]%'", [U.pentester.id]) > 0);
    });
    test("el panel sigue leyendo los logs como antes", async () => {
      const r = await pedir("GET", `/api/engagements/${E.a}/phases/recon/logs`, { bearer: token("pentester") });
      assert.equal(r.status, 200); assert.ok(r.json.length > 0);
    });
    test("las tablas se crean una sola vez: un segundo arranque no falla", async () => {
      const { crearTablas } = require("../agentes/esquema");
      await crearTablas({ qRun: (s) => pool.query(s) });
      assert.ok(!/no se pudieron crear las tablas/.test(salida), salida);
    });
  });
});

describe("arsenal", () => {
  test("data/arsenal.json está al día con el panel (npm run arsenal)", (t) => {
    const { extraer, DESTINO, FUENTE } = require("../agentes/extraer-arsenal");
    if (!fs.existsSync(FUENTE)) return t.skip("sin el código del panel");
    assert.deepEqual(JSON.parse(fs.readFileSync(DESTINO, "utf8")), extraer());
  });
});

describe("CVE", () => {
  const cve = require("../agentes/cve");
  const nvd = { vulnerabilities: [{ cve: { descriptions: [{ lang: "en", value: "bug" }], metrics: { cvssMetricV31: [{ cvssData: { vectorString: "CVSS:3.1/AV:N", baseScore: 9.8, baseSeverity: "CRITICAL" } }] }, weaknesses: [{ description: [{ value: "CWE-79" }] }] } }] };
  test("resume y recuerda la respuesta", async () => {
    let n = 0;
    const buscar = cve.crear({ pedir: async () => { n++; return { status: 200, data: JSON.stringify(nvd) }; } });
    const r = await buscar("CVE-2024-1234"); await buscar("CVE-2024-1234");
    assert.equal(n, 1); assert.equal(r.cvss_vector_31, "AV:N"); assert.equal(r.severity, "critical"); assert.equal(r.cwe_id, "CWE-79");
  });
  test("traduce los errores de NVD", async () => {
    for (const [status, data, codigo] of [[429, "", 503], [403, "", 503], [500, "", 503], [404, "", 404], [200, '{"vulnerabilities":[]}', 404], [200, "<html>mantenimiento</html>", 503], [200, "{}", 503]])
      await assert.rejects(cve.crear({ pedir: async () => ({ status, data }) })("CVE-2024-1234"), (e) => e.codigo === codigo);
    await assert.rejects(cve.crear({ pedir: async () => { throw new Error("red"); } })("CVE-2024-1234"), (e) => e.codigo === 503);
  });
});
