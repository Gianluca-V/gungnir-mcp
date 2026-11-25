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
    test("🔴 no se modifica un hallazgo cuyo activo quedó fuera de alcance, y un activo ilegible no lo impide", async () => {
      for (const k of ["propuesta", "escritura"]) {
        const fid = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo())).json.hallazgo_id;
        const cambiar = (b) => ag(k, "PUT", `/engagements/${E.a}/hallazgos/${fid}`, b);
        for (const activo of ["8.8.8.8", "10.10.5.5"]) {
          await sql("UPDATE findings SET affected_asset=? WHERE id=?", [activo, fid]);
          const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
          assert.equal((await cambiar({ severity: "low" })).status, 422, activo);
          assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 1);
        }
        // Cambiarle el activo en el mismo pedido no lo saltea: lo corrige una persona.
        for (const activo of ["8.8.8.8", "evil.test", "https://evil.test/x", "evil.test:443", "8.8.0.0/24", "evil.test (prod)", "srv (8.8.8.8) 443/tcp", "10.10.1.1, 8.8.8.8", "Portal 10.10.5.5", "[2001:db8::9]:443"]) {
          await sql("UPDATE findings SET affected_asset=? WHERE id=?", [activo, fid]);
          assert.equal((await cambiar({ affected_asset: "10.10.1.1", title: uid() })).status, 422, activo);
          assert.equal((await cambiar({ severity: "low" })).status, 422, activo);
        }
        // Una etiqueta de una persona o del seguimiento no es un objetivo: no se juzga ni se denuncia.
        const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
        for (const activo of ["srv-web (10.10.1.1) 80/tcp", "", null, "Portal", "Aplicación web", "N/A", "Dockerfile", "src/db.js:42", "org/app", "github.com/org/app src/db.js:42", "srv-web", "s3://balde", "server.js", "10.10.1.1:80/tcp", "app.ejemplo.com", "https://app.ejemplo.com/x", "v1.2.3"]) {
          await sql("UPDATE findings SET affected_asset=? WHERE id=?", [activo, fid]);
          assert.ok([200, 202].includes((await cambiar({ severity: "low", description: uid() })).status), String(activo));
        }
        assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes);
      }
    });
    test("🔴 sin alcance cargado, una etiqueta tampoco impide completar un hallazgo", async () => {
      const antes = await sql("SELECT * FROM scope_items WHERE engagement_id=?", [E.a]);
      const fid = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo())).json.hallazgo_id;
      try {
        await sql("DELETE FROM scope_items WHERE engagement_id=?", [E.a]);
        await sql("UPDATE findings SET affected_asset='Portal' WHERE id=?", [fid]);
        assert.equal((await ag("escritura", "PUT", `/engagements/${E.a}/hallazgos/${fid}`, { severity: "low" })).status, 200);
        await sql("UPDATE findings SET affected_asset='10.10.1.1' WHERE id=?", [fid]);
        assert.equal((await ag("escritura", "PUT", `/engagements/${E.a}/hallazgos/${fid}`, { severity: "low" })).status, 422);
      } finally { for (const a of antes) await sql("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,?,?,?)", [a.id, E.a, a.type, a.value, a.in_scope]); }
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
    test("🔴 si otro quita el acceso a la vez, se audita lo que se intentó y no que quedó visible", async () => {
      await sql("CREATE TRIGGER quita_acceso BEFORE UPDATE ON agente_engagements FOR EACH ROW SET NEW.mostrar_sensibles=0");
      try { assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "lectura", mostrar_sensibles: true })).status, 409); }
      finally { await sql("DROP TRIGGER IF EXISTS quita_acceso"); }
      const d = (await sql("SELECT detail FROM audit_logs WHERE action='agente_acceso' AND entity_id=? ORDER BY created_at DESC, id LIMIT 50", [E.a])).map((x) => x.detail);
      assert.ok(d.some((x) => /se pidió mostrar datos sensibles y otro cambio los dejó ocultos/.test(x)));
      await acceso("a", "total", false);
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
    test("🔴 un acceso quitado con datos visibles de antes no los muestra al habilitarlo", async () => {
      try {
        await sql("REPLACE INTO agente_engagements (engagement_id,nivel_max,mostrar_sensibles) VALUES (?,'ninguno',1)", [E.a]);
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "lectura" })).status, 200);
        assert.equal((await sql("SELECT mostrar_sensibles FROM agente_engagements WHERE engagement_id=?", [E.a]))[0].mostrar_sensibles, 0);
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "total", mostrar_sensibles: true })).status, 200);
        assert.equal((await panel("auditor", "PUT", `/engagements/${E.a}`, { nivel_max: "lectura" })).status, 200);
        assert.equal((await sql("SELECT mostrar_sensibles FROM agente_engagements WHERE engagement_id=?", [E.a]))[0].mostrar_sensibles, 1);
      } finally { await acceso("a", "total", false); }
    });
    test("🔴 un archivo enorme se revisa entero: cuenta lo que pasa la severidad y deja constancia de cada equipo fuera", async () => {
      // 23 es de severidad alta para el lector de nmap; los puertos 30000 y siguientes, informativos.
      const puerto = (p) => `<port protocol="tcp" portid="${p}"><state state="open"/></port>`;
      const puertos = (ip, desde, n, nombre) => `<host><status state="up"/><address addr="${ip}" addrtype="ipv4"/>${nombre ? `<hostnames><hostname name="${nombre}" type="user"/></hostnames>` : ""}<ports>${Array.from({ length: n }, (_, i) => puerto(desde + i)).join("")}</ports></host>`;
      const grande = `<nmaprun>${puertos("10.10.8.1", 23, 1)}${puertos("10.10.8.1", 30000, 20100)}${puertos("8.8.4.9", 30000, 1)}</nmaprun>`;
      const subir = (contenido, severidad_minima) => ag("escritura", "POST", `/engagements/${E.a}/importar`, { formato: "nmap", severidad_minima }, { archivo: { nombre: "s.xml", contenido } });
      const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
      const r = await subir(grande, "high");
      assert.equal(r.status, 201, r.texto);
      assert.equal(r.json.hallazgos_creados, 1);
      assert.equal(r.json.leidos, 20102);
      assert.equal(r.json.bajo_severidad_minima, 20100);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 1);
      assert.equal((await subir(grande, "info")).status, 413);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 2);
      // Un puerto excluido del mismo equipo, al final del archivo, también se detecta.
      await conAlcance([["cidr", "10.10.0.0/16", 1], ["ip", "10.10.8.1:65000", 0]], async () => {
        const x = await subir(`<nmaprun>${puertos("10.10.8.1", 30000, 20100)}${puertos("10.10.8.1", 65000, 1)}</nmaprun>`, "high");
        assert.equal(x.status, 201, x.texto);
        assert.deepEqual(x.json.hosts_fuera_de_alcance, ["10.10.8.1"]);
      });
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
    test("🔴 si el alcance cambia mientras se lee el archivo, vale el nuevo", async () => {
      // El engagement tomado desde afuera detiene la importación entre la lectura y el guardado.
      const con = await pool.getConnection();
      try {
        await con.beginTransaction();
        await con.query("SELECT id FROM engagements WHERE id=? FOR UPDATE", [E.a]);
        const x = importar("escritura", "nmap", nmap("10.10.44.4", 8044));
        await new Promise((ok) => setTimeout(ok, 500));
        await con.query("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,'ip','10.10.44.4',0)", [uid(), E.a]);
        await con.commit();
        const r = await x;
        assert.equal(r.status, 201, r.texto);
        assert.equal(r.json.hallazgos_creados, 0); assert.deepEqual(r.json.hosts_fuera_de_alcance, ["10.10.44.4"]);
      } finally { await con.rollback(); con.release(); await sql("DELETE FROM scope_items WHERE engagement_id=? AND value='10.10.44.4'", [E.a]); }
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
    test("🔴 el conflicto mira el contenido: ni un cambio en el mismo segundo se escapa, ni hay falsos avisos", async () => {
      for (const [accion, datos] of [["", { recommendation: "x" }], ["/retest", { resultado: "failed", notas: "x" }]]) {
        const proponer2 = async () => {
          const fid = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo())).json.hallazgo_id;
          const r = await ag("propuesta", accion ? "POST" : "PUT", `/engagements/${E.a}/hallazgos/${fid}${accion}`, datos);
          assert.equal(r.status, 202, r.texto);
          return { fid, p: r.json.propuesta_id };
        };
        const a = await proponer2(); // Recién creado, en el mismo segundo: no cambió nada.
        assert.equal((await panel("lector", "GET", `/propuestas/${a.p}`)).json.cambio, false);
        assert.equal((await panel("auditor", "POST", `/propuestas/${a.p}/aprobar`)).status, 200);
        for (const set of ["description='otra'", "risk_accepted_reason='x'", "remediation_due_date='2031-01-01'", "retest_notes='otra'"]) {
          const b = await proponer2();
          await sql(`UPDATE findings SET ${set}, updated_at=updated_at WHERE id=?`, [b.fid]);
          assert.equal((await panel("auditor", "POST", `/propuestas/${b.p}/aprobar`)).json.conflicto, true, set);
          assert.equal((await panel("auditor", "POST", `/propuestas/${b.p}/aprobar`, { forzar: true })).status, 200);
        }
      }
      // Lo propuesto antes de esta versión se sigue controlando por fecha.
      const fid = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo())).json.hallazgo_id;
      const p = (await ag("propuesta", "PUT", `/engagements/${E.a}/hallazgos/${fid}`, { severity: "low" })).json.propuesta_id;
      await sql("UPDATE agente_propuestas SET huella=NULL WHERE id=?", [p]);
      await sql("UPDATE findings SET updated_at=NOW() + INTERVAL 5 SECOND WHERE id=?", [fid]);
      assert.equal((await panel("auditor", "POST", `/propuestas/${p}/aprobar`)).json.conflicto, true);
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

  describe("editar antes de aprobar", () => {
    const proponer = async (h = hallazgo()) => ({ h, id: (await ag("propuesta", "POST", `/engagements/${E.a}/hallazgos`, h)).json.propuesta_id });
    const aprobar = (id, body, rol = "auditor") => panel(rol, "POST", `/propuestas/${id}/aprobar`, body);
    const fila = async (id) => (await sql("SELECT * FROM agente_propuestas WHERE id=?", [id]))[0];
    const json = (v) => (typeof v === "string" ? JSON.parse(v) : v);
    test("🔴 se guarda lo editado, se conserva lo propuesto, se audita y el agente ve qué campos cambiaron", async () => {
      const { h, id } = await proponer(hallazgo({ description: "Texto del agente" }));
      const r = await aprobar(id, { datos: { ...h, severity: "low", recommendation: "Parchear" } });
      assert.equal(r.status, 200, r.texto);
      const f = (await sql("SELECT * FROM findings WHERE id=?", [r.json.finding_id]))[0];
      assert.deepEqual([f.severity, f.initial_severity, f.recommendation, f.description], ["low", "low", "Parchear", "Texto del agente"]);
      const p = await fila(id);
      assert.equal(json(p.datos).severity, "high");
      assert.equal(json(p.datos_aprobados).severity, "low");
      const visto = (await ag("propuesta", "GET", `/engagements/${E.a}/propuestas?estado=aprobada`)).json.datos.find((x) => x.id === id);
      assert.deepEqual(visto.campos_editados.sort(), ["recommendation", "severity"]);
      assert.equal(await contar("audit_logs", "action='agente_propuesta_aprobar' AND entity_id=? AND detail LIKE '%Editada: %severity%'", [r.json.finding_id]), 1);
    });
    test("🔴 aprobar sin editar sigue igual, y mandar lo mismo no cuenta como edición", async () => {
      for (const cuerpo of [(h) => undefined, (h) => ({}), (h) => ({ datos: { ...h } })]) {
        const { h, id } = await proponer();
        const r = await aprobar(id, cuerpo(h));
        assert.equal(r.status, 200, r.texto);
        const p = await fila(id);
        assert.equal(p.datos_aprobados, null); assert.equal(p.campos_editados, null);
        assert.equal((await ag("propuesta", "GET", `/engagements/${E.a}/propuestas?estado=aprobada`)).json.datos.find((x) => x.id === id).campos_editados, null);
      }
    });
    test("un espacio de más en lo propuesto no cuenta como edición", async () => {
      const { h, id } = await proponer();
      await sql("UPDATE agente_propuestas SET datos=JSON_SET(datos,'$.title',?) WHERE id=?", [`${h.title} `, id]);
      assert.equal((await aprobar(id, { datos: { ...h, severity: "low" } })).status, 200);
      assert.deepEqual(json((await fila(id)).campos_editados), ["severity"]);
    });
    test("🔴 lo editado pasa las mismas reglas: campos, valores, alcance, marcas y duplicados", async () => {
      const { h, id } = await proponer();
      for (const [datos, codigo] of [
        [{ ...h, severity: "grave" }, 400], [{ ...h, status: "accepted" }, 400], [{ ...h, created_by: U.admin.id }, 400], [{ ...h, title: "" }, 400],
        [{ ...h, cvss_score_31: 11 }, 400], [{ ...h, description: "[OCULTO:cred:0a1b2c]" }, 400], [null, 400], [[], 400], ["x", 400],
        [{ severity: "low" }, 400], [{ ...h, affected_asset: "8.8.8.8" }, 409], [{ ...h, affected_asset: "10.10.5.5" }, 409],
      ]) assert.equal((await aprobar(id, { datos })).status, codigo, JSON.stringify(datos));
      const otro = hallazgo();
      assert.equal((await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, otro)).status, 201);
      assert.equal((await aprobar(id, { datos: { ...h, title: otro.title } })).status, 409);
      assert.equal((await aprobar(id, { datos: h }, "lector")).status, 403);
      assert.equal((await fila(id)).estado, "pendiente");
      assert.equal(await contar("findings", "title=?", [h.title]), 0);
      // Corregir el activo que salió del alcance permite aprobarla.
      await sql("UPDATE scope_items SET in_scope=0 WHERE engagement_id=? AND value='10.10.0.0/16'", [E.a]);
      const x = await aprobar(id, {}), y = await aprobar(id, { datos: { ...h, affected_asset: "app.ejemplo.com" } });
      await sql("UPDATE scope_items SET in_scope=1 WHERE engagement_id=? AND value='10.10.0.0/16'", [E.a]);
      assert.equal(x.status, 409); assert.equal(y.status, 200, y.texto);
    });
    test("🔴 en un cambio se puede corregir o sacar un campo, y lo demás no se toca", async () => {
      const fid = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ description: "original", recommendation: "original" }))).json.hallazgo_id;
      const id = (await ag("propuesta", "PUT", `/engagements/${E.a}/hallazgos/${fid}`, { severity: "critical", description: "del agente" })).json.propuesta_id;
      assert.equal((await aprobar(id, { datos: {} })).status, 400);
      await sql("UPDATE findings SET updated_at=NOW() - INTERVAL 1 HOUR WHERE id=?", [fid]);
      const r = await aprobar(id, { datos: { severity: "medium" } });
      assert.equal(r.status, 200, r.texto);
      const f = (await sql("SELECT severity,description,recommendation FROM findings WHERE id=?", [fid]))[0];
      assert.deepEqual({ ...f }, { severity: "medium", description: "original", recommendation: "original" });
      assert.deepEqual(json((await fila(id)).campos_editados).sort(), ["description", "severity"]);
    });
    test("🔴 el detalle trae el valor actual de lo que cambia y avisa si se tocó después", async () => {
      const fid = (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ description: "original", references_list: ["https://a"] }))).json.hallazgo_id;
      await sql("UPDATE findings SET updated_at=NOW() - INTERVAL 1 HOUR WHERE id=?", [fid]);
      const id = (await ag("propuesta", "PUT", `/engagements/${E.a}/hallazgos/${fid}`, { description: "nuevo", references_list: ["https://b"] })).json.propuesta_id;
      let d = (await panel("lector", "GET", `/propuestas/${id}`)).json;
      assert.deepEqual(d.actual, { description: "original", references_list: ["https://a"] });
      assert.deepEqual(d.datos, { description: "nuevo", references_list: ["https://b"] });
      assert.equal(d.cambio, false);
      await sql("UPDATE findings SET owasp_category='cambió' WHERE id=?", [fid]);
      assert.equal((await panel("lector", "GET", `/propuestas/${id}`)).json.cambio, true);
      // Con conflicto, lo editado se puede forzar.
      assert.equal((await aprobar(id, { datos: { description: "corregido" } })).json.conflicto, true);
      assert.equal((await aprobar(id, { datos: { description: "corregido" }, forzar: true })).status, 200);
      assert.equal((await sql("SELECT description FROM findings WHERE id=?", [fid]))[0].description, "corregido");
      const nueva = await proponer();
      d = (await panel("lector", "GET", `/propuestas/${nueva.id}`)).json;
      assert.equal(d.actual, null); assert.equal(d.datos.title, nueva.h.title);
      assert.equal((await panel("lector", "GET", `/propuestas/${uid()}`)).status, 404);
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

  describe("retest", () => {
    const alta = async (extra = {}) => (await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo(extra))).json.hallazgo_id;
    const viejo = (id) => sql("UPDATE findings SET updated_at=NOW() - INTERVAL 1 HOUR WHERE id=?", [id]);
    const reprobar = (key, id, b, e = E.a) => ag(key, "POST", `/engagements/${e}/hallazgos/${id}/retest`, b);
    const aprobar = (id, body, rol = "auditor") => panel(rol, "POST", `/propuestas/${id}/aprobar`, body);
    const f = async (id) => (await sql("SELECT status,severity,retest_status,retest_severity,retest_notes,retested_by,retested_at FROM findings WHERE id=?", [id]))[0];
    const OK = { resultado: "passed", notas: "Ya no responde a la comprobación." };
    test("🔴 en todo nivel es una propuesta y no toca el hallazgo", async () => {
      for (const k of ["propuesta", "escritura", "total"]) {
        const id = await alta(), antes = await f(id);
        const r = await reprobar(k, id, OK);
        assert.equal(r.status, 202, r.texto);
        assert.equal(r.json.estado, "pendiente");
        assert.deepEqual(await f(id), antes);
      }
      assert.equal((await reprobar("lectura", await alta(), OK)).status, 403);
    });
    test("🔴 al aprobar hace lo mismo que el retest del panel", async () => {
      for (const [b, status, sev] of [[OK, "fixed", "info"], [{ resultado: "failed", notas: "Sigue igual" }, "open", "high"],
        [{ resultado: "partial", retest_severity: "low", notas: "Mitigado" }, "in_remediation", "low"]]) {
        const id = await alta(); await viejo(id);
        const p = (await reprobar("propuesta", id, b)).json.propuesta_id;
        const r = await aprobar(p);
        assert.equal(r.status, 200, r.texto); assert.equal(r.json.finding_id, id);
        const x = await f(id);
        assert.deepEqual([x.status, x.retest_status, x.retest_severity, x.retest_notes, x.retested_by, x.severity], [status, b.resultado, sev, b.notas, U.auditor.id, "high"]);
        assert.ok(x.retested_at);
        assert.equal(await contar("audit_logs", "action='finding_retest' AND entity_id=? AND user_id=? AND detail LIKE ?", [E.a, U.auditor.id, `% → ${b.resultado}`]) > 0, true);
      }
    });
    test("el retest del panel sigue igual que antes", async () => {
      for (const [b, status, sev] of [[{ result: "passed" }, "fixed", "info"], [{ result: "failed", notes: "x" }, "open", "high"], [{ result: "partial", retest_severity: "medium" }, "in_remediation", "medium"],
        [{ result: "failed", retest_severity: "rara" }, "open", "high"]]) {
        const id = await alta();
        const r = await pedir("POST", `/api/engagements/${E.a}/findings/${id}/retest`, { bearer: token("pentester"), body: b });
        assert.equal(r.status, 200, r.texto);
        assert.deepEqual([r.json.status, r.json.retest_status, r.json.retest_severity, r.json.retest_notes, r.json.retested_by], [status, b.result, sev, b.notes ?? null, U.pentester.id]);
      }
      assert.equal((await pedir("POST", `/api/engagements/${E.a}/findings/${uid()}/retest`, { bearer: token("pentester"), body: { result: "passed" } })).status, 404);
      assert.equal((await pedir("POST", `/api/engagements/${E.a}/findings/${await alta()}/retest`, { bearer: token("pentester"), body: { result: "x" } })).status, 400);
    });
    test("🔴 valida lo que llega, y no admite una severidad que se ignoraría", async () => {
      const id = await alta();
      for (const b of [{}, { resultado: "passed" }, { notas: "x" }, { resultado: "ok", notas: "x" }, { ...OK, notas: "" }, { ...OK, status: "fixed" }, { ...OK, retest_severity: "low" },
        { resultado: "failed", retest_severity: "grave", notas: "x" }, { ...OK, notas: "[OCULTO:cred:0a1b2c]" }, { ...OK, notas: { a: 1 } }, { ...OK, objetivo: ["x"] }, []])
        assert.equal((await reprobar("propuesta", id, b)).status, 400, JSON.stringify(b));
      assert.equal((await reprobar("propuesta", uid(), OK)).status, 404);
      assert.equal(await contar("agente_propuestas", "finding_id=?", [id]), 0);
    });
    test("🔴 respeta el alcance al proponer y al aprobar", async () => {
      const id = await alta();
      const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
      for (const objetivo of ["8.8.8.8", "10.10.5.5"]) assert.equal((await reprobar("propuesta", id, { ...OK, objetivo })).status, 422);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 2);
      // Un activo escrito por una persona puede no ser un objetivo: se indica cuál se probó.
      await sql("UPDATE findings SET affected_asset='srv-web (10.10.1.1) 80/tcp' WHERE id=?", [id]);
      assert.equal((await reprobar("propuesta", id, OK)).status, 422);
      await viejo(id);
      const p = (await reprobar("propuesta", id, { ...OK, objetivo: "10.10.1.1:80" })).json.propuesta_id;
      assert.ok(p);
      await sql("UPDATE scope_items SET in_scope=0 WHERE engagement_id=? AND value='10.10.0.0/16'", [E.a]);
      const r = await aprobar(p);
      await sql("UPDATE scope_items SET in_scope=1 WHERE engagement_id=? AND value='10.10.0.0/16'", [E.a]);
      assert.equal(r.status, 409);
      assert.equal((await f(id)).retest_status, "not_retested");
      assert.equal((await aprobar(p)).status, 200);
    });
    test("🔴 no reprueba un riesgo aceptado por una persona, ni antes ni después de proponerlo", async () => {
      const id = await alta(), otro = await alta();
      await sql("UPDATE findings SET status='accepted' WHERE id=?", [id]);
      assert.equal((await reprobar("total", id, OK)).status, 409);
      const p = (await reprobar("propuesta", otro, OK)).json.propuesta_id;
      await sql("UPDATE findings SET status='accepted' WHERE id=?", [otro]);
      for (const b of [{}, { forzar: true }]) assert.equal((await aprobar(p, b)).status, 409);
      assert.equal((await f(otro)).status, "accepted");
    });
    test("🔴 un retest pendiente por hallazgo, aunque lleguen a la vez", async () => {
      const id = await alta();
      const r = await Promise.all([1, 2, 3, 4].map(() => reprobar("propuesta", id, OK)));
      assert.deepEqual(r.map((x) => x.status).sort(), [202, 409, 409, 409]);
      const p = r.find((x) => x.status === 202).json.propuesta_id;
      assert.equal(r.find((x) => x.status === 409).json.existente.id, p);
      assert.equal((await panel("auditor", "POST", `/propuestas/${p}/rechazar`, { motivo: "Falta evidencia" })).status, 200);
      assert.equal((await reprobar("propuesta", id, OK)).status, 202);
    });
    test("avisa si el hallazgo cambió en el medio, y se puede editar o forzar", async () => {
      const id = await alta(); await viejo(id);
      const p = (await reprobar("propuesta", id, { resultado: "failed", notas: "Sigue" })).json.propuesta_id;
      let d = (await panel("lector", "GET", `/propuestas/${p}`)).json;
      assert.equal(d.accion, "retest"); assert.equal(d.cambio, false);
      assert.deepEqual(d.datos, { resultado: "failed", objetivo: "10.10.1.1:80/tcp", notas: "Sigue" });
      assert.deepEqual(d.actual, { resultado: "not_retested", objetivo: "10.10.1.1:80/tcp", retest_severity: null, notas: null });
      await sql("UPDATE findings SET owasp_category='cambió' WHERE id=?", [id]);
      const datos = { ...d.datos, resultado: "partial", retest_severity: "medium" };
      assert.equal((await aprobar(p, { datos })).json.conflicto, true);
      assert.equal((await aprobar(p, { datos: { ...datos, notas: "" }, forzar: true })).status, 400);
      assert.equal((await aprobar(p, { datos: { ...datos, objetivo: "8.8.8.8" }, forzar: true })).status, 409);
      assert.equal((await aprobar(p, { datos, forzar: true })).status, 200);
      assert.deepEqual([(await f(id)).retest_status, (await f(id)).retest_severity], ["partial", "medium"]);
      d = (await ag("propuesta", "GET", `/engagements/${E.a}/propuestas?estado=aprobada`)).json.datos.find((x) => x.id === p);
      assert.deepEqual([d.accion, d.resultado, d.campos_editados.sort()], ["retest", "failed", ["resultado", "retest_severity"]]);
    });
    test("el agente ve el estado del retest y filtra por él", async () => {
      const id = await alta();
      await sql("UPDATE findings SET remediation_due_date='2030-05-07' WHERE id=?", [id]);
      await viejo(id);
      const listar = async (q) => (await ag("lectura", "GET", `/engagements/${E.a}/hallazgos?limite=100&${q}`)).json.datos.find((x) => x.id === id);
      assert.deepEqual([(await listar("retest=not_retested")).retest_status, (await listar("retest=not_retested")).remediation_due_date], ["not_retested", "2030-05-07"]);
      await aprobar((await reprobar("propuesta", id, { resultado: "failed", notas: "nota larga" })).json.propuesta_id);
      assert.equal(await listar("retest=not_retested"), undefined);
      assert.equal((await listar("retest=failed")).id, id);
      assert.equal((await ag("lectura", "GET", `/engagements/${E.a}/hallazgos?retest=x`)).status, 400);
      const d = (await ag("lectura", "GET", `/engagements/${E.a}/hallazgos/${id}`)).json.datos;
      assert.deepEqual([d.retest_status, d.retest_severity, d.retest_notes], ["failed", "high", "nota larga"]);
    });
    test("en lote y en la actividad", async () => {
      const id = await alta(); await viejo(id);
      const p = (await reprobar("propuesta", id, OK)).json.propuesta_id;
      assert.deepEqual((await panel("auditor", "POST", "/propuestas/aprobar-lote", { ids: [p] })).json.aprobadas, [p]);
      assert.equal((await f(id)).status, "fixed");
      for (let i = 0; i < 40; i++) {
        const d = (await panel("admin", "GET", `/keys/${keys.propuesta_id}/actividad`)).json.datos[0];
        if (d.accion === "retest") return assert.equal(d.codigo, 202);
        await new Promise((ok) => setTimeout(ok, 50));
      }
      assert.fail("no quedó en la actividad");
    });
    test("🔴 una instalación con el esquema anterior admite los tipos nuevos sin perder datos", async () => {
      const { crearTablas } = require("../agentes/esquema");
      const n = await contar("agente_propuestas", "accion IN ('crear','actualizar')");
      await sql("DELETE FROM agente_propuestas WHERE accion NOT IN ('crear','actualizar')");
      await sql("ALTER TABLE agente_propuestas MODIFY accion ENUM('crear','actualizar') NOT NULL");
      const q = { qRun: (s, p) => pool.query(s, p), qRows: async (s, p) => (await pool.query(s, p))[0] };
      await crearTablas(q); await crearTablas(q);
      assert.equal(await contar("agente_propuestas"), n);
      assert.equal((await reprobar("propuesta", await alta(), OK)).status, 202);
    });
  });

  describe("Attack Map", () => {
    const mandar = (key, equipos, e = E.a, extra) => ag(key, "POST", `/engagements/${e}/mapa`, { equipos }, extra);
    const ver = async (key = "lectura", q = "?limite=100") => (await ag(key, "GET", `/engagements/${E.a}/mapa${q}`)).json;
    const uno = async (o) => (await ver()).datos.find((x) => x.objetivos.includes(o));
    const equipos = () => contar("engagement_targets", "engagement_id=?", [E.a]);
    const limpio = () => sql("DELETE FROM engagement_targets WHERE engagement_id=?", [E.a]);
    const aprobar = (id, body) => panel("auditor", "POST", `/propuestas/${id}/aprobar`, body);
    const agregar = async (c) => { const id = uid(); await sql("INSERT INTO engagement_targets (id,engagement_id,ip_address,fqdn,url_address,os_type,notes,owned,jumped_from_id) VALUES (?,?,?,?,?,?,?,?,?)", [id, E.a, c.ip ?? null, c.fqdn ?? null, c.url ?? null, c.os ?? "other", c.notas ?? null, c.owned ? 1 : 0, c.desde ?? null]); return id; };
    const COMPLETO = { objetivo: "10.10.1.1", os_type: "linux", notas: "DMZ", puertos: [{ puerto: 22, servicio: "ssh", producto: "OpenSSH", version: "9.6" }, { puerto: 53, protocolo: "udp" }] };
    before(limpio); after(limpio);
    test("🔴 en Escritura guarda, en Propuesta espera aprobación y en Lectura no entra", async () => {
      await limpio();
      const p = await mandar("propuesta", [COMPLETO]);
      assert.equal(p.status, 202, p.texto); assert.equal(await equipos(), 0);
      assert.equal((await mandar("lectura", [COMPLETO])).status, 403);
      const r = await mandar("escritura", [COMPLETO, { objetivo: "app.ejemplo.com", desde: "10.10.1.1", comprometido: true }]);
      assert.equal(r.status, 200, r.texto);
      assert.deepEqual([r.json.equipos_nuevos, r.json.puertos_nuevos, r.json.pivotes_nuevos], [2, 2, 1]);
      const m = await panel("lector", "GET", "/resumen") && (await pedir("GET", `/api/engagements/${E.a}/attack-map`, { bearer: token("lector") })).json;
      const n = m.nodes.find((x) => x.ip === "10.10.1.1"), h = m.nodes.find((x) => x.fqdn === "app.ejemplo.com");
      assert.equal(n.type, "linux"); assert.equal(n.notes, "DMZ"); assert.deepEqual(n.ports.map((x) => [x.port, x.proto, x.service]), [[22, "tcp", "ssh OpenSSH 9.6"], [53, "udp", ""]]);
      assert.equal(h.owned, true); assert.deepEqual(m.edges, [{ from: n.id, to: h.id }]);
      // Aprobar lo que ya está no duplica.
      assert.equal((await aprobar(p.json.propuesta_id)).status, 200);
      assert.equal(await equipos(), 2);
      assert.equal(await contar("target_ports", "engagement_id=?", [E.a]), 2);
    });
    test("🔴 aprobar una propuesta la lleva al mapa, y queda auditada en el engagement", async () => {
      await limpio();
      const p = (await mandar("propuesta", [COMPLETO])).json.propuesta_id;
      const d = (await panel("lector", "GET", `/propuestas/${p}`)).json;
      assert.equal(d.accion, "mapa"); assert.equal(d.datos.equipos[0].objetivo, "10.10.1.1");
      const r = await aprobar(p);
      assert.equal(r.status, 200, r.texto); assert.equal(r.json.finding_id, null);
      assert.deepEqual((await uno("10.10.1.1")).puertos.map((x) => x.puerto), [22, 53]);
      assert.equal(await contar("audit_logs", "action='agente_propuesta_aprobar' AND entity='engagements' AND entity_id=?", [E.a]) > 0, true);
    });
    test("🔴 completa lo vacío y nunca pisa ni borra lo que cargó una persona", async () => {
      await limpio();
      const otro = await agregar({ ip: "10.10.1.9" });
      const id = await agregar({ ip: "10.10.1.1", os: "windows", notas: "de una persona", owned: true, desde: otro });
      await sql("INSERT INTO target_ports (id,target_id,engagement_id,port_number,protocol,service_name) VALUES (?,?,?,22,'tcp','ssh-persona')", [uid(), id, E.a]);
      const r = await mandar("escritura", [COMPLETO, { objetivo: "10.10.1.2" }, { objetivo: "10.10.1.1".replace("1.1", "1.3"), desde: "10.10.1.2" }]);
      assert.equal(r.status, 200, r.texto);
      const x = (await mandar("escritura", [{ ...COMPLETO, desde: "10.10.1.2" }])).json;
      assert.deepEqual(x.conservados.map((c) => c.campo).sort(), ["desde", "notas", "os_type", "puerto 22/tcp: servicio"]);
      const f = (await sql("SELECT * FROM engagement_targets WHERE id=?", [id]))[0];
      assert.deepEqual([f.os_type, f.notes, f.owned, f.jumped_from_id], ["windows", "de una persona", 1, otro]);
      const p = (await sql("SELECT service_name, product, version FROM target_ports WHERE target_id=? AND port_number=22", [id]))[0];
      assert.deepEqual({ ...p }, { service_name: "ssh-persona", product: "OpenSSH", version: "9.6" });
    });
    test("reconoce un equipo por cualquiera de sus nombres, sin importar mayúsculas", async () => {
      await limpio();
      await agregar({ ip: "10.10.1.1", fqdn: "App.Ejemplo.com" });
      const r = (await mandar("escritura", [{ objetivo: "app.ejemplo.COM", os_type: "linux" }])).json;
      assert.deepEqual([r.equipos_nuevos, await equipos()], [0, 1]);
      assert.equal((await uno("10.10.1.1")).os_type, "linux");
    });
    test("🔴 un equipo fuera de alcance rechaza todo y deja constancia", async () => {
      await limpio();
      const antes = await contar("agente_violaciones", "engagement_id=?", [E.a]);
      for (const k of ["propuesta", "escritura"]) {
        const r = await mandar(k, [{ objetivo: "10.10.1.1" }, { objetivo: "8.8.8.8" }, { objetivo: "10.10.5.5", puertos: [{ puerto: 80 }] }]);
        assert.equal(r.status, 422, r.texto); assert.match(r.json.error, /8\.8\.8\.8/);
      }
      assert.equal(await equipos(), 0);
      assert.equal(await contar("agente_violaciones", "engagement_id=?", [E.a]), antes + 4);
      assert.equal(await contar("agente_propuestas", "engagement_id=? AND accion='mapa' AND datos LIKE '%8.8.8.8%'", [E.a]), 0);
    });
    test("🔴 con un puerto excluido, se anotan los demás puertos y no el excluido", async () => {
      await limpio();
      const id = uid();
      await sql("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,'ip','10.10.1.7:22',0)", [id, E.a]);
      try {
        assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.7", puertos: [{ puerto: 443 }] }])).status, 200);
        assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.7", puertos: [{ puerto: 443 }, { puerto: 22 }] }])).status, 422);
        assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.7" }])).status, 422);
      } finally { await sql("DELETE FROM scope_items WHERE id=?", [id]); }
    });
    test("🔴 el alcance se vuelve a controlar al aprobar, y lo editado pasa las mismas reglas", async () => {
      await limpio();
      const p = (await mandar("propuesta", [{ objetivo: "10.10.1.1" }, { objetivo: "app.ejemplo.com" }])).json.propuesta_id;
      await sql("UPDATE scope_items SET in_scope=0 WHERE engagement_id=? AND value='app.ejemplo.com'", [E.a]);
      const r = await aprobar(p);
      const s = await aprobar(p, { datos: { equipos: [{ objetivo: "10.10.1.1" }, { objetivo: "8.8.8.8" }] } });
      const v = await aprobar(p, { datos: { equipos: [] } });
      const ok = await aprobar(p, { datos: { equipos: [{ objetivo: "10.10.1.1" }] } });
      await sql("UPDATE scope_items SET in_scope=1 WHERE engagement_id=? AND value='app.ejemplo.com'", [E.a]);
      assert.deepEqual([r.status, s.status, v.status, ok.status], [409, 409, 400, 200], ok.texto);
      assert.equal(await equipos(), 1);
      assert.deepEqual((await ag("propuesta", "GET", `/engagements/${E.a}/propuestas?estado=aprobada`)).json.datos.find((x) => x.id === p).campos_editados, ["equipos"]);
    });
    test("🔴 pivotes: solo entre equipos del mapa o del pedido, sin ciclos y sin apuntarse a sí mismo", async () => {
      await limpio();
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.1", desde: "10.10.1.2" }])).status, 422);
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.1", desde: "10.10.1.1" }])).status, 422);
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.1", desde: "10.10.1.2" }, { objetivo: "10.10.1.2", desde: "10.10.1.1" }])).status, 422);
      assert.equal(await equipos(), 0, "un pedido con error no deja nada a medias");
      await agregar({ fqdn: "kali-atacante", os: "kali" });
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.1", desde: "kali-atacante" }, { objetivo: "10.10.1.2", desde: "10.10.1.1" }])).status, 200);
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.3", desde: "10.10.1.2" }])).status, 200);
      assert.equal((await uno("10.10.1.3")).desde, "10.10.1.2");
      await sql("UPDATE engagement_targets SET jumped_from_id=NULL WHERE engagement_id=? AND ip_address='10.10.1.1'", [E.a]);
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.1", desde: "10.10.1.3" }])).status, 422);
    });
    test("🔴 lo que una persona guarda mientras el agente escribe no se pierde", async () => {
      for (const via of ["directo", "aprobar"]) {
        await limpio();
        const id = await agregar({ ip: "10.10.1.2" }), otro = await agregar({ fqdn: "kali", os: "kali" }), mio = await agregar({ ip: "10.10.1.3" });
        const equipos2 = [{ objetivo: "10.10.1.1", puertos: [{ puerto: 4444 }] }, { objetivo: "10.10.1.2", os_type: "windows", notas: "AGENTE", desde: "10.10.1.3" }];
        const p = via === "aprobar" ? (await mandar("propuesta", equipos2)).json.propuesta_id : null;
        await sql("CREATE TRIGGER puerto_lento BEFORE INSERT ON target_ports FOR EACH ROW BEGIN IF NEW.port_number=4444 THEN DO SLEEP(0.8); END IF; END");
        try {
          const enVuelo = p ? aprobar(p) : mandar("escritura", equipos2);
          await new Promise((ok) => setTimeout(ok, 300));
          const h = await pedir("PUT", `/api/engagements/${E.a}/targets/${id}`, { bearer: token("pentester"), body: { os_type: "linux", notes: "HUMANO", jumped_from_id: otro } });
          assert.equal(h.status, 200); assert.equal((await enVuelo).status, 200);
        } finally { await sql("DROP TRIGGER IF EXISTS puerto_lento"); }
        const f = (await sql("SELECT os_type,notes,jumped_from_id FROM engagement_targets WHERE id=?", [id]))[0];
        assert.deepEqual({ ...f }, { os_type: "linux", notes: "HUMANO", jumped_from_id: otro }, `${via} ${mio}`);
      }
    });
    test("🔴 aprobar dos a la vez, o aprobar mientras otro escribe, no duplica equipos", async () => {
      for (const directo of [false, true]) {
        await limpio(); await sql("DELETE FROM agente_propuestas WHERE accion='mapa'");
        const ids = [];
        for (const notas of ["una", "dos"]) ids.push((await mandar("propuesta", [{ objetivo: "10.10.4.4", notas, puertos: [{ puerto: 22 }] }])).json.propuesta_id);
        const con = await pool.getConnection();
        await con.beginTransaction();
        await con.query("SELECT id FROM engagements WHERE id=? FOR UPDATE", [E.a]);
        const r = Promise.all([aprobar(ids[0]), directo ? mandar("escritura", [{ objetivo: "10.10.4.4" }]) : aprobar(ids[1])]);
        await new Promise((ok) => setTimeout(ok, 500));
        await con.commit(); con.release();
        assert.deepEqual((await r).map((x) => x.status), [200, 200]);
        assert.equal(await equipos(), 1);
      }
    });
    test("🔴 lo que no se aplicó de un puerto se informa, también a quien aprueba", async () => {
      await limpio();
      const id = await agregar({ ip: "10.10.1.1" });
      await sql("INSERT INTO target_ports (id,target_id,engagement_id,port_number,state,service_name,product,version) VALUES (?,?,?,22,'open','ssh','OpenSSH','7.4'),(?,?,?,80,'closed',NULL,NULL,NULL)", [uid(), id, E.a, uid(), id, E.a]);
      const e = [{ objetivo: "10.10.1.1", puertos: [{ puerto: 22, servicio: "telnet", producto: "OpenSSH", version: "2020" }, { puerto: 80, servicio: "http" }] }];
      const campos = ["puerto 22/tcp: servicio", "puerto 22/tcp: version", "puerto 80/tcp: estado closed"];
      const r = (await mandar("escritura", e)).json;
      assert.deepEqual(r.conservados.map((x) => x.campo), campos);
      assert.equal(r.puertos_nuevos, 0);
      const p = (await mandar("propuesta", e)).json.propuesta_id;
      assert.deepEqual((await aprobar(p)).json.resultado.conservados.map((x) => x.campo), campos);
      const f = await sql("SELECT port_number,state,service_name,product,version FROM target_ports WHERE target_id=? ORDER BY port_number", [id]);
      assert.deepEqual(f.map((x) => ({ ...x })), [{ port_number: 22, state: "open", service_name: "ssh", product: "OpenSSH", version: "7.4" }, { port_number: 80, state: "closed", service_name: null, product: null, version: null }]);
      await sql("UPDATE target_ports SET version='' WHERE target_id=? AND port_number=22", [id]);
      assert.equal((await mandar("escritura", e)).json.puertos_completados, 1);
    });
    test("el detalle dice de dónde sale cada pivote, para poder sacar equipos sin romperlo", async () => {
      await limpio(); await sql("DELETE FROM agente_propuestas WHERE accion='mapa'");
      await agregar({ ip: "10.10.1.9" });
      const p = (await mandar("propuesta", [{ objetivo: "10.10.1.1" }, { objetivo: "10.10.1.2", desde: "::ffff:10.10.1.1" }, { objetivo: "10.10.1.3", desde: "10.10.1.9" }, { objetivo: "10.10.1.9" }])).json.propuesta_id;
      assert.deepEqual((await panel("lector", "GET", `/propuestas/${p}`)).json.actual, { origenes: { "::ffff:10.10.1.1": { en_mapa: false, en_pedido: "10.10.1.1" }, "10.10.1.9": { en_mapa: true, en_pedido: "10.10.1.9" } } });
    });
    test("🔴 aprobar sin cambios desde el diálogo no cuenta como edición", async () => {
      await limpio(); await sql("DELETE FROM agente_propuestas WHERE accion='mapa'");
      const p = (await mandar("propuesta", [COMPLETO])).json.propuesta_id;
      const d = (await panel("auditor", "GET", `/propuestas/${p}`)).json.datos;
      assert.equal((await aprobar(p, { datos: { equipos: d.equipos } })).status, 200);
      const f = (await sql("SELECT campos_editados, datos_aprobados FROM agente_propuestas WHERE id=?", [p]))[0];
      assert.deepEqual({ ...f }, { campos_editados: null, datos_aprobados: null });
    });
    test("🔴 el mismo equipo escrito de otra forma es el mismo equipo", async () => {
      await limpio();
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.3.3" }])).json.equipos_nuevos, 1);
      for (const o of ["::ffff:10.10.3.3", "[::ffff:10.10.3.3]", "１０.10.3.3"]) assert.equal((await mandar("escritura", [{ objetivo: o }])).json.equipos_nuevos, 0, o);
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.3.4" }, { objetivo: "::ffff:10.10.3.4" }])).status, 400);
      assert.equal((await mandar("escritura", [{ objetivo: "app。ejemplo。com" }, { objetivo: "10.10.3.5", desde: "APP.ejemplo.com." }])).status, 200);
      assert.deepEqual((await sql("SELECT COALESCE(ip_address,fqdn) AS n FROM engagement_targets WHERE engagement_id=? ORDER BY n", [E.a])).map((x) => x.n), ["10.10.3.3", "10.10.3.5", "app.ejemplo.com"]);
    });
    test("en una URL importan las mayúsculas de la ruta, y no se admiten credenciales", async () => {
      await limpio();
      assert.equal((await mandar("escritura", [{ objetivo: "https://app.ejemplo.com/Admin" }, { objetivo: "https://app.ejemplo.com/admin" }])).json.equipos_nuevos, 2);
      assert.equal((await mandar("escritura", [{ objetivo: "HTTPS://APP.ejemplo.com/Admin" }])).json.equipos_nuevos, 0);
      const r = await mandar("escritura", [{ objetivo: "https://u:Sup3rClave9@app.ejemplo.com/x" }]);
      assert.equal(r.status, 400); assert.ok(!r.texto.includes("Sup3rClave9"));
    });
    test("🔴 no toca el mapa de otro engagement", async () => {
      await limpio();
      const id = uid();
      await sql("INSERT INTO engagement_targets (id,engagement_id,ip_address) VALUES (?,?,'10.10.1.1')", [id, E.b]);
      assert.equal((await mandar("escritura", [{ ...COMPLETO }], E.b)).status, 404);
      assert.equal((await mandar("escritura", [COMPLETO])).json.equipos_nuevos, 1);
      assert.equal((await sql("SELECT os_type FROM engagement_targets WHERE id=?", [id]))[0].os_type, "other");
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.4", desde: "10.10.9.9" }])).status, 422);
      await sql("DELETE FROM engagement_targets WHERE id=?", [id]);
    });
    test("🔴 tipos y formas inesperados dan 400 y no guardan nada", async () => {
      await limpio();
      for (const e of [undefined, null, [], {}, "x", [null], ["10.10.1.1"], [{}], [{ objetivo: "" }], [{ objetivo: 5 }], [{ objetivo: "10.10.0.0/24" }], [{ objetivo: "10.10.1.1-5" }], [{ objetivo: "10.10.1.1:80" }],
        [{ objetivo: "*.ejemplo.com" }], [{ objetivo: "10.10.1.1 10.10.1.2" }], [{ objetivo: "app.ejemplo.com/x" }], [{ objetivo: "ftp://app.ejemplo.com/" }], [{ objetivo: "10.10.1.1" }, { objetivo: "10.10.1.1" }],
        [{ objetivo: "10.10.1.1", os_type: "temple" }], [{ objetivo: "10.10.1.1", owned: 1 }], [{ objetivo: "10.10.1.1", comprometido: false }], [{ objetivo: "10.10.1.1", comprometido: "si" }],
        [{ objetivo: "10.10.1.1", puertos: {} }], [{ objetivo: "10.10.1.1", puertos: [80] }], [{ objetivo: "10.10.1.1", puertos: [{ puerto: 0 }] }], [{ objetivo: "10.10.1.1", puertos: [{ puerto: 65536 }] }],
        [{ objetivo: "10.10.1.1", puertos: [{ puerto: "80" }] }], [{ objetivo: "10.10.1.1", puertos: [{ puerto: 80, protocolo: "icmp" }] }], [{ objetivo: "10.10.1.1", puertos: [{ puerto: 80 }, { puerto: 80 }] }],
        [{ objetivo: "10.10.1.1", puertos: [{ puerto: 80, state: "x" }] }], [{ objetivo: "https://app.ejemplo.com/", puertos: [{ puerto: 80 }] }], [{ objetivo: "10.10.1.1", notas: "[OCULTO:cred:0a1b2c]" }],
        Array.from({ length: 51 }, (_, i) => ({ objetivo: `10.10.2.${i}` })), [{ objetivo: "10.10.1.1", puertos: Array.from({ length: 1001 }, (_, i) => ({ puerto: i + 1 })) }]])
        assert.equal((await mandar("escritura", e)).status, 400, JSON.stringify(e)?.slice(0, 120));
      assert.equal((await ag("escritura", "POST", `/engagements/${E.a}/mapa`, { equipos: [COMPLETO], otro: 1 })).status, 400);
      assert.equal(await equipos(), 0);
    });
    test("acepta IPv6, nombres y URL", async () => {
      await limpio();
      const id = uid();
      await sql("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,'ip','2001:db8::5',1)", [id, E.a]);
      try {
        const r = await mandar("escritura", [{ objetivo: "2001:db8::5", puertos: [{ puerto: 443 }] }, { objetivo: "app.ejemplo.com" }, { objetivo: "https://app.ejemplo.com/Login" }]);
        assert.equal(r.status, 200, r.texto);
        const f = await sql("SELECT ip_address,fqdn,url_address FROM engagement_targets WHERE engagement_id=? ORDER BY ip_address DESC, fqdn DESC", [E.a]);
        assert.deepEqual(f.map((x) => ({ ...x })), [{ ip_address: "2001:db8::5", fqdn: null, url_address: null }, { ip_address: null, fqdn: "app.ejemplo.com", url_address: null }, { ip_address: null, fqdn: null, url_address: "https://app.ejemplo.com/Login" }]);
      } finally { await sql("DELETE FROM scope_items WHERE id=?", [id]); }
    });
    test("🔴 iguales a la vez no duplican equipos, y un reintento no repite", async () => {
      await limpio();
      const r = await Promise.all(Array.from({ length: 6 }, () => mandar("escritura", [COMPLETO])));
      assert.ok(r.every((x) => x.status === 200), r.map((x) => x.texto).join());
      assert.equal(await equipos(), 1); assert.equal(r.reduce((n, x) => n + x.json.equipos_nuevos, 0), 1);
      assert.equal(r.reduce((n, x) => n + x.json.puertos_nuevos, 0), 2);
      const k = { headers: { "Idempotency-Key": uid() } };
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.8" }], E.a, k)).json.equipos_nuevos, 1);
      assert.equal((await mandar("escritura", [{ objetivo: "10.10.1.8" }], E.a, k)).json.equipos_nuevos, 1);
      assert.equal(await equipos(), 2);
    });
    test("🔴 una propuesta igual a una pendiente se rechaza, y hay tope de pendientes", async () => {
      await sql("DELETE FROM agente_propuestas WHERE accion='mapa'");
      const p = (await mandar("propuesta", [COMPLETO])).json.propuesta_id;
      assert.equal((await mandar("propuesta", [{ ...COMPLETO, puertos: [...COMPLETO.puertos].reverse() }])).status, 409);
      const r = await mandar("propuesta", [{ puertos: COMPLETO.puertos, notas: "DMZ", os_type: "linux", objetivo: "10.10.1.1" }]);
      assert.equal(r.status, 409); assert.equal(r.json.existente.id, p);
      assert.equal((await mandar("propuesta", [{ objetivo: "10.10.2.1" }, { objetivo: "10.10.2.2", desde: "10.10.2.1" }])).status, 202);
      assert.equal((await mandar("propuesta", [{ objetivo: "::ffff:10.10.2.1" }, { objetivo: "10.10.2.2", desde: "::ffff:10.10.2.1" }])).status, 409);
      for (let i = 0; i < 48; i++) assert.equal((await mandar("propuesta", [{ objetivo: `10.10.3.${i}` }])).status, 202);
      assert.equal((await mandar("propuesta", [{ objetivo: "10.10.3.99" }])).status, 409);
      await sql("DELETE FROM agente_propuestas WHERE accion='mapa'");
    });
    test("🔴 la lectura se pagina, oculta secretos y no nombra al cliente", async () => {
      await limpio();
      const a = await agregar({ ip: "10.10.1.1", notas: "Banco Ficticio password=Sup3rClave9" });
      await agregar({ ip: "10.10.1.2", desde: a }); await agregar({ fqdn: "app.ejemplo.com" });
      await sql("INSERT INTO target_ports (id,target_id,engagement_id,port_number,state) VALUES (?,?,?,23,'closed'),(?,?,?,80,'open')", [uid(), a, E.a, uid(), a, E.a]);
      const x = await uno("10.10.1.1");
      assert.ok(!/Sup3rClave9|Banco Ficticio/.test(JSON.stringify(x)));
      assert.deepEqual(x.puertos.map((p) => p.puerto), [80]);
      assert.equal((await uno("10.10.1.2")).desde, "10.10.1.1");
      const uno1 = await ver("lectura", "?limite=2"), dos = await ver("lectura", `?limite=2&desde=${uno1.siguiente}`);
      assert.deepEqual([uno1.datos.length, uno1.hay_mas, dos.datos.length, dos.hay_mas], [2, true, 1, false]);
      assert.equal(uno1.contenido_no_confiable, true);
    });
    test("las notas largas salen recortadas y completo=1 trae más", async () => {
      await limpio();
      await agregar({ ip: "10.10.1.1", notas: "n".repeat(4000) });
      assert.match((await uno("10.10.1.1")).notas, /\[RECORTADO: faltan \d+ caracteres\]/);
      assert.equal((await ver("lectura", "?completo=1")).datos[0].notas.length, 4000);
    });
    test("🔴 la lista del panel va recortada y el detalle completo", async () => {
      await limpio(); await sql("DELETE FROM agente_propuestas WHERE accion='mapa'");
      const p = (await mandar("propuesta", [{ objetivo: "10.10.1.1", notas: "n".repeat(4500), puertos: Array.from({ length: 100 }, (_, i) => ({ puerto: i + 1 })) }])).json.propuesta_id;
      const h = (await ag("propuesta", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ description: "d".repeat(50000) }))).json.propuesta_id;
      const l = (await panel("lector", "GET", "/propuestas")).json, lm = l.find((x) => x.id === p), lh = l.find((x) => x.id === h);
      assert.equal(lm.datos.equipos[0].puertos.length, 20); assert.equal(lm.datos.equipos[0].puertos_total, 100);
      assert.ok(JSON.stringify(lm).length < 3000); assert.ok(JSON.stringify(lh).length < 7000);
      assert.match(lh.datos.description, /\[RECORTADO:/);
      const dm = (await panel("lector", "GET", `/propuestas/${p}`)).json.datos, dh = (await panel("lector", "GET", `/propuestas/${h}`)).json.datos;
      assert.equal(dm.equipos[0].puertos.length, 100); assert.equal(dm.equipos[0].notas.length, 4500); assert.equal(dh.description.length, 50000);
      assert.equal((await aprobar(p)).status, 200);
      assert.equal(await contar("target_ports", "engagement_id=?", [E.a]), 100);
      const r = await panel("auditor", "POST", `/propuestas/${h}/aprobar`);
      assert.equal((await sql("SELECT LENGTH(description) AS n FROM findings WHERE id=?", [r.json.finding_id]))[0].n, 50000);
    });
    test("🔴 un archivo de puertos enorme no inunda la lectura", async () => {
      await limpio();
      const a = await agregar({ ip: "10.10.1.1" });
      await sql("INSERT INTO target_ports (id,target_id,engagement_id,port_number) VALUES ?", [Array.from({ length: 500 }, (_, i) => [uid(), a, E.a, i + 1])]);
      const x = await uno("10.10.1.1");
      assert.equal(x.puertos.length, 200); assert.equal(x.puertos_total, 500);
    });
    test("queda en la actividad con sus equipos", async () => {
      await mandar("escritura", [{ objetivo: "10.10.1.1" }, { objetivo: "10.10.1.2" }]);
      for (let i = 0; i < 40; i++) {
        const d = (await panel("admin", "GET", `/keys/${keys.escritura_id}/actividad`)).json.datos[0];
        if (d.accion === "mapa" && d.objetivo === "10.10.1.1, 10.10.1.2") return;
        await new Promise((ok) => setTimeout(ok, 50));
      }
      assert.fail("no quedó en la actividad");
    });
  });

  describe("actividad por key", () => {
    const ver = (rol, key, q = "") => panel(rol, "GET", `/keys/${keys[`${key}_id`]}/actividad${q}`);
    // Se anota sin demorar la respuesta: se espera a que aparezca.
    async function esperar(key, cumple, q = "") {
      for (let i = 0; ; i++) {
        const r = await ver("admin", key, q);
        if (cumple(r.json?.datos || [])) return r.json.datos;
        if (i > 60) assert.fail(JSON.stringify(r.json).slice(0, 1500));
        await new Promise((ok) => setTimeout(ok, 50));
      }
    }
    before(async () => { await nuevaKey("act", "pentester", "escritura", [E.a]); });
    test("🔴 muestra escrituras y rechazos con su engagement, de lo más nuevo a lo más viejo, y no las lecturas", async () => {
      const h = hallazgo();
      assert.equal((await ag("act", "GET", `/engagements/${E.a}/hallazgos`)).status, 200);
      assert.equal((await ag("act", "POST", `/engagements/${E.a}/alcance/verificar`, { objetivos: ["10.10.1.1"] })).status, 200);
      assert.equal((await ag("act", "POST", `/engagements/${E.a}/hallazgos`, h)).status, 201);
      assert.equal((await ag("act", "POST", `/engagements/${E.a}/logs`, { fase: "recon", objetivo: "10.10.1.1", herramienta: "nmap", comando: "nmap 10.10.1.1" })).status, 201);
      assert.equal((await ag("act", "DELETE", `/engagements/${E.a}/logs/${uid()}`)).status, 403);
      assert.equal((await ag("act", "GET", `/engagements/${E.b}`)).status, 404);
      const d = await esperar("act", (x) => x.length === 4);
      assert.deepEqual(d.map((x) => [x.accion, x.codigo, x.fuera]), [["consulta", 404, false], ["log_borrar", 403, false], ["log", 201, false], ["hallazgo_crear", 201, false]]);
      assert.equal(d[3].objetivo, `${h.title} · ${h.affected_asset}`);
      assert.equal(d[3].engagement_title, "Pentest Banco Ficticio a");
      assert.equal(d[2].detalle, "nmap 10.10.1.1");
      assert.match(d[1].detalle, /nivel "total"/);
      assert.equal(d[1].engagement_title, "Pentest Banco Ficticio a");
      assert.equal(d[0].engagement_title, null, "uno ajeno no se nombra");
    });
    test("🔴 marca lo que quedó fuera de alcance, se haya guardado o rechazado", async () => {
      await ag("act", "POST", `/engagements/${E.a}/logs`, { fase: "recon", objetivo: "8.8.8.8", comando: "ping 8.8.8.8" });
      await ag("act", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ affected_asset: "8.8.8.8" }));
      const d = await esperar("act", (x) => x.length === 2, "?filtro=fuera");
      assert.deepEqual(d.map((x) => x.codigo), [422, 201]);
      const r = await esperar("act", (x) => x.length === 3, "?filtro=rechazos");
      assert.ok(r.every((x) => x.codigo >= 400));
      assert.equal((await ver("admin", "act", "?filtro=otro")).status, 400);
    });
    test("🔴 lo rechazado que se repite se agrupa, y una escritura que se guarda no", async () => {
      await nuevaKey("act2", "pentester", "escritura", [E.a]);
      const id = uid();
      for (let i = 0; i < 5; i++) await ag("act2", "DELETE", `/engagements/${E.a}/logs/${id}`);
      const log = { fase: "recon", notas: "igual" };
      for (let i = 0; i < 2; i++) await ag("act2", "POST", `/engagements/${E.a}/logs`, log);
      await ag("act2", "DELETE", `/engagements/${E.a}/logs/${id}`);
      const d = await esperar("act2", (x) => x.length === 4);
      assert.deepEqual(d.map((x) => [x.accion, x.veces]), [["log_borrar", 1], ["log", 1], ["log", 1], ["log_borrar", 5]]);
    });
    test("🔴 la ve su dueño y el admin; nadie más, y ningún agente", async () => {
      assert.equal((await ver("pentester", "act")).status, 200);
      for (const rol of ["auditor", "lector"]) assert.equal((await ver(rol, "act")).status, 404);
      assert.equal((await ver("pentester", "total")).status, 404);
      assert.equal((await ag("act", "GET", `/keys/${keys.act_id}/actividad`)).status, 404);
    });
    test("🔴 usar una key revocada queda en su actividad; una inventada no deja nada", async () => {
      await nuevaKey("act3", "pentester", "lectura", [E.a]);
      const total = () => contar("agente_actividad", "key_id IN (SELECT id FROM agente_keys WHERE user_id IN (?))", [Object.values(U).map((x) => x.id)]);
      assert.equal((await panel("admin", "DELETE", `/keys/${keys.act3_id}`)).status, 200);
      const antes = await total();
      await ag("gnga_" + "2".repeat(64), "GET", "/yo");
      await ag("act3", "GET", "/yo");
      const d = await esperar("act3", (x) => x.length === 1);
      assert.match(d[0].detalle, /revocada/);
      assert.equal(d[0].codigo, 401);
      // Insistir con objetivos distintos no hace crecer la tabla, aunque además supere el límite.
      for (let i = 0; i < 30; i++) await ag("act3", "POST", `/engagements/${E.a}/logs`, { fase: "recon", objetivo: `10.10.1.${i}`, comando: "x" });
      const e = await esperar("act3", (x) => x.length === 1 && x[0].veces === 31);
      assert.deepEqual([e[0].accion, e[0].objetivo], ["acceso", null]);
      assert.equal(await total(), antes + 1);
      assert.equal(await total(), antes + 1);
    });
    test("se pagina hacia atrás sin repetir ni saltear", async () => {
      await nuevaKey("act4", "pentester", "escritura", [E.a]);
      for (let i = 0; i < 60; i++) await ag("act4", "POST", `/engagements/${E.a}/logs`, { fase: "recon", notas: `n${i}` });
      const uno = await esperar("act4", (x) => x.length === 50 && x[0].id);
      let r = await ver("admin", "act4");
      for (let i = 0; i < 40 && Number((await sql("SELECT COUNT(*) AS n FROM agente_actividad WHERE key_id=?", [keys.act4_id]))[0].n) < 60; i++) await new Promise((ok) => setTimeout(ok, 50));
      r = await ver("admin", "act4");
      const dos = await ver("admin", "act4", `?antes=${r.json.siguiente}`);
      assert.equal(uno.length, 50);
      assert.equal(dos.json.datos.length, 10);
      assert.equal(dos.json.siguiente, null);
      assert.equal(new Set([...r.json.datos, ...dos.json.datos].map((x) => x.id)).size, 60);
      assert.equal((await ver("admin", "act4", "?antes=x")).status, 400);
    });
    test("🔴 pasada la cantidad de rechazos distintos por ventana, el resto va a una sola fila", async () => {
      await nuevaKey("act6", "pentester", "lectura", [E.a]);
      for (let i = 0; i < 230; i++) await ag("act6", "DELETE", `/engagements/${E.a}/logs/${uid()}`);
      const n = () => contar("agente_actividad", "key_id=?", [keys.act6_id]);
      const d = await esperar("act6", (x) => x[0]?.veces === 30);
      assert.equal(d[0].objetivo, null);
      assert.equal(await n(), 201);
    });
    test("🔴 pasado el tope, lo que estaba fuera de alcance igual se ve en ese filtro", async () => {
      await nuevaKey("act9", "pentester", "escritura", [E.a]);
      for (let i = 0; i < 201; i++) await ag("act9", "DELETE", `/engagements/${E.a}/logs/${uid()}`);
      assert.equal((await ver("admin", "act9", "?filtro=fuera")).json.datos.length, 0);
      await ag("act9", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ affected_asset: "8.8.8.8" }));
      await esperar("act9", (x) => x.length === 1 && x[0].veces === 2, "?filtro=fuera");
    });
    test("🔴 un cuerpo ilegible o demasiado grande también queda, gasta cupo y pide autenticarse", async () => {
      await nuevaKey("act10", "pentester", "escritura", [E.a]);
      const crudo = (body, bearer = keys.act10) => fetch(`${base}${V1}/engagements/${E.a}/logs`, { method: "POST", headers: { Authorization: `Bearer ${bearer}`, "Content-Type": "application/json" }, body });
      const a = await crudo("{mal"), b = await crudo(JSON.stringify({ notas: "x".repeat(3 * 1024 * 1024) })), x = await crudo("{mal", "gnga_" + "3".repeat(64));
      assert.equal(a.status, 400); assert.match((await a.json()).error, /JSON/);
      assert.equal(b.status, 413); assert.ok([401, 429].includes(x.status));
      assert.equal(Number(b.headers.get("ratelimit-remaining")), Number(a.headers.get("ratelimit-remaining")) - 1);
      const d = await esperar("act10", (y) => y.length === 2);
      assert.deepEqual(d.map((y) => [y.accion, y.codigo]), [["log", 413], ["log", 400]]);
      const gz = await fetch(`${base}${V1}/engagements/${E.a}/logs`, { method: "POST", headers: { Authorization: `Bearer ${keys.act10}`, "Content-Type": "application/json", "Content-Encoding": "gzip" }, body: Buffer.from("no es gzip") });
      assert.equal(gz.status, 400);
      const cupo = async () => Number((await ag("act10", "GET", "/yo")).headers.get("ratelimit-remaining")), c0 = await cupo();
      for (const u of ["/engagements/%", "/engagements/%E0%A4%A"]) assert.equal((await ag("act10", "GET", u)).status, 400, u);
      assert.equal(await cupo(), c0 - 3, "cada pedido gasta una vez");
      assert.equal((await fetch(`${base}${V1}/engagements/%`)).status === 400, false, "sin key no entra");
      const p = await fetch(`${base}/api/agentes/pausa`, { method: "POST", headers: { Authorization: `Bearer ${token("admin")}`, "Content-Type": "application/json" }, body: "{mal" });
      assert.equal(p.status, 400, "el panel sigue igual");
    });
    test("🔴 se conserva 90 días: lo viejo no se muestra y se borra todo, sea cuanto sea", async () => {
      const { limpiar } = require("../agentes/actividad");
      const vieja = Array.from({ length: 3000 }, () => [keys.act_id, "log", 201, "vieja", new Date(Date.now() - 120 * 864e5)]);
      for (let i = 0; i < 4; i++) await sql("INSERT INTO agente_actividad (key_id,accion,codigo,objetivo,ultima_en) VALUES ?", [vieja]);
      let antes = null;
      do {
        const r = (await ver("admin", "act", antes ? `?antes=${antes}` : "")).json;
        assert.ok(r.datos.every((x) => x.objetivo !== "vieja"));
        antes = r.siguiente;
      } while (antes);
      const recientes = await contar("agente_actividad", "objetivo IS NULL OR objetivo<>'vieja'");
      await limpiar((q, p) => pool.query(q, p));
      assert.equal(await contar("agente_actividad", "objetivo='vieja'"), 0);
      assert.equal(await contar("agente_actividad"), recientes);
    });
    test("🔴 el comando se lee del log: si se borra el log, no queda en la actividad", async () => {
      await nuevaKey("act7", "pentester", "escritura", [E.a]);
      const r = await ag("act7", "POST", `/engagements/${E.a}/logs`, { fase: "recon", objetivo: "10.10.1.1", comando: "mysql -pSuperSecreta" });
      const d = await esperar("act7", (x) => x.length === 1);
      assert.equal(d[0].detalle, "mysql -pSuperSecreta");
      await sql("DELETE FROM operation_logs WHERE id=?", [r.json.id]);
      assert.equal((await ver("admin", "act7")).json.datos[0].detalle, null);
      assert.equal(await contar("agente_actividad", "detalle LIKE '%SuperSecreta%'"), 0);
    });
    test("las rutas se reconocen sin importar mayúsculas", async () => {
      await nuevaKey("act8", "pentester", "escritura", [E.a]);
      assert.equal((await ag("act8", "POST", `/engagements/${E.a}/Alcance/Verificar`, { objetivos: ["10.10.1.1"] })).status, 200);
      assert.equal((await ag("act8", "POST", `/engagements/${E.a}/LOGS`, { fase: "recon", notas: "x" })).status, 201);
      const d = await esperar("act8", (x) => x.length >= 1);
      assert.deepEqual(d.map((x) => x.accion), ["log"]);
    });
    test("🔴 si no se puede anotar, la escritura responde igual", async () => {
      await sql("RENAME TABLE agente_actividad TO agente_actividad_x");
      try { assert.equal((await ag("act", "POST", `/engagements/${E.a}/logs`, { fase: "recon", notas: "x" })).status, 201); }
      finally { await sql("RENAME TABLE agente_actividad_x TO agente_actividad"); }
    });
    test("un reintento con la misma clave cuenta una vez, y los datos raros no rompen nada", async () => {
      await nuevaKey("act5", "pentester", "escritura", [E.a]);
      const k = { headers: { "Idempotency-Key": uid() } }, log = { fase: "recon", notas: "una" };
      for (let i = 0; i < 3; i++) assert.equal((await ag("act5", "POST", `/engagements/${E.a}/logs`, log, k)).status, 201);
      assert.equal((await ag("act5", "POST", `/engagements/${E.a}/logs`, { fase: "recon", objetivo: { a: 1 }, comando: ["x"] })).status, 400);
      const d = await esperar("act5", (x) => x.length === 2);
      assert.equal(d[0].objetivo, null);
    });
  });

  describe("pausa", () => {
    const pausar = (rol, pausado, e) => panel(rol, "POST", e ? `/engagements/${E[e]}/pausa` : "/pausa", { pausado });
    const reanudarTodo = async () => { await pausar("admin", false); await pausar("admin", false, "a"); };
    test("🔴 la pausa global corta lectura y escritura de todas las keys, y al reanudar vuelven", async () => {
      try {
        assert.equal((await pausar("pentester", true)).status, 200);
        for (const [k, m, r, b] of [["lectura", "GET", "/yo"], ["lectura", "GET", "/arsenal"], ["total", "GET", `/engagements/${E.a}`], ["escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo()]]) {
          const x = await ag(k, m, r, b);
          assert.equal(x.status, 423, `${m} ${r}`);
          assert.equal(x.json.pausado, true);
          assert.match(x.json.error, /pausa/);
        }
        const s = (await panel("lector", "GET", "/resumen")).json;
        assert.equal(s.pausa.por, `pentester-${suf}`);
        assert.ok(s.pausa.desde);
      } finally { await reanudarTodo(); }
      assert.equal((await ag("lectura", "GET", "/yo")).status, 200);
      assert.equal((await panel("lector", "GET", "/resumen")).json.pausa, null);
    });
    test("🔴 la pausa de un engagement no afecta a los demás, y no revela uno ajeno", async () => {
      await acceso("b", "total");
      try {
        assert.equal((await pausar("pentester", true, "a")).status, 200);
        assert.equal((await ag("total", "GET", `/engagements/${E.a}`)).status, 423);
        assert.equal((await ag("total", "GET", "/yo")).status, 200);
        assert.equal((await ag("delB", "GET", `/engagements/${E.b}`)).status, 200);
        assert.equal((await ag("delB", "GET", `/engagements/${E.a}`)).status, 404);
        assert.equal((await ag("total", "GET", "/engagements")).json.datos.find((e) => e.id === E.a).pausado, true);
        assert.ok((await panel("lector", "GET", "/engagements")).json.find((e) => e.id === E.a).pausado_en);
      } finally { await reanudarTodo(); await acceso("b", "ninguno"); }
      assert.equal((await ag("total", "GET", `/engagements/${E.a}`)).status, 200);
    });
    test("🔴 pausa quien decide y reanuda quien administra accesos", async () => {
      try {
        assert.equal((await pausar("lector", true)).status, 403);
        assert.equal((await pausar("pentester", true)).status, 200);
        assert.equal((await pausar("pentester", true, "a")).status, 200);
        assert.equal((await pausar("pentester", false)).status, 403);
        assert.equal((await pausar("pentester", false, "a")).status, 403);
        assert.equal((await ag("total", "POST", "/pausa", { pausado: false })).status, 423);
        assert.notEqual((await pedir("POST", "/api/agentes/pausa", { bearer: keys.total, body: { pausado: false } })).status, 200);
        assert.ok((await panel("lector", "GET", "/resumen")).json.pausa);
        assert.equal((await pausar("auditor", false)).status, 200);
        assert.equal((await pausar("auditor", false, "a")).status, 200);
      } finally { await reanudarTodo(); }
    });
    test("🔴 confirmada la pausa, una escritura que ya estaba en curso no se guarda", async () => {
      for (const e of [undefined, "a"]) {
        const titulo = `En curso ${uid()}`, clave = { headers: { "Idempotency-Key": uid() } };
        const cuerpo = hallazgo({ title: titulo });
        const con = await pool.getConnection();
        try {
          await con.beginTransaction();
          await con.query("SELECT id FROM engagements WHERE id=? FOR UPDATE", [E.a]);
          const enVuelo = ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, cuerpo, clave);
          await new Promise((ok) => setTimeout(ok, 300));
          assert.equal((await pausar("pentester", true, e)).status, 200);
          await con.commit();
          const r = await enVuelo;
          assert.equal(r.status, 423, r.texto);
          assert.equal(await contar("findings", "title=?", [titulo]), 0);
        } finally { await con.rollback(); con.release(); await reanudarTodo(); }
        const r = await ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, cuerpo, clave);
        assert.equal(r.status, 201, r.texto); // La clave quedó libre para reintentar.
      }
    });
    test("🔴 tampoco si la transacción ya había leído antes de la pausa", async () => {
      const titulo = `lenta ${uid()}`;
      await sql("CREATE TRIGGER alta_lenta BEFORE INSERT ON findings FOR EACH ROW BEGIN IF NEW.title LIKE 'lenta%' THEN DO SLEEP(0.8); END IF; END");
      try {
        const enVuelo = ag("escritura", "POST", `/engagements/${E.a}/hallazgos`, hallazgo({ title: titulo }));
        await new Promise((ok) => setTimeout(ok, 300));
        assert.equal((await pausar("pentester", true)).status, 200);
        assert.equal((await enVuelo).status, 423);
        assert.equal(await contar("findings", "title=?", [titulo]), 0);
      } finally { await reanudarTodo(); await sql("DROP TRIGGER IF EXISTS alta_lenta"); }
    });
    test("🔴 una subida pausada a mitad no deja el archivo en disco", async () => {
      const carpeta = path.join(BACKEND, "..", "uploads"), antes = fs.readdirSync(carpeta).length;
      const con = await pool.getConnection();
      try {
        await con.beginTransaction();
        await con.query("SELECT id FROM engagements WHERE id=? FOR UPDATE", [E.a]);
        const x = ag("escritura", "POST", `/engagements/${E.a}/importar`, { formato: "nmap" }, { archivo: { nombre: "s.xml", contenido: `<nmaprun><host><status state="up"/><address addr="10.10.9.9" addrtype="ipv4"/><ports><port protocol="tcp" portid="99"><state state="open"/></port></ports></host></nmaprun>` } });
        await new Promise((ok) => setTimeout(ok, 300));
        assert.equal((await pausar("pentester", true)).status, 200);
        await con.commit();
        assert.equal((await x).status, 423);
      } finally { await con.rollback(); con.release(); await reanudarTodo(); }
      assert.equal(fs.readdirSync(carpeta).length, antes);
    });
    test("pausar no cambia niveles ni keys, queda auditado y valida lo que recibe", async () => {
      const acc = () => sql("SELECT nivel_max, mostrar_sensibles FROM agente_engagements WHERE engagement_id=?", [E.a]);
      const antes = await acc();
      try {
        assert.equal((await pausar("pentester", true)).status, 200);
        assert.equal((await pausar("pentester", true, "a")).status, 200);
        assert.deepEqual(await acc(), antes);
        await acceso("a", "total"); // Cambiar el nivel de algo pausado no lo reanuda.
        assert.equal((await pausar("admin", false)).status, 200);
        assert.equal((await ag("total", "GET", `/engagements/${E.a}`)).status, 423);
      } finally { await reanudarTodo(); }
      assert.ok(await contar("audit_logs", "action='agente_pausa' AND username=?", [`pentester-${suf}`]) >= 2);
      for (const b of [{}, { pausado: "si" }, { pausado: 1 }]) assert.equal((await panel("admin", "POST", "/pausa", b)).status, 400);
      assert.equal((await panel("admin", "POST", `/engagements/${uid()}/pausa`, { pausado: true })).status, 404);
      await sql("DELETE FROM agente_engagements WHERE engagement_id=?", [E.b]);
      assert.equal((await pausar("admin", true, "b")).status, 409, "sin acceso no hay nada que pausar");
    });
    test("🔴 los pedidos en pausa gastan el cupo de la key: insistir no es gratis", async () => {
      try {
        const antes = Number((await ag("lectura", "GET", "/yo")).headers.get("ratelimit-remaining"));
        assert.equal((await pausar("admin", true)).status, 200);
        const r = await ag("lectura", "GET", "/yo");
        assert.equal(r.status, 423);
        assert.equal(Number(r.headers.get("ratelimit-remaining")), antes - 1);
      } finally { await reanudarTodo(); }
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
  describe("explotación: KEV y EPSS", () => {
    const base = ({ kev = null, epss = null, catalogo = 1500, bajado = new Date() } = {}) => async (q) =>
      (/COUNT/.test(q) ? { n: catalogo, actualizado: bajado } : /vuln_kev/.test(q) ? kev : /vuln_epss/.test(q) ? epss : assert.fail(q));
    const first = (epss, percentile = 0.9) => JSON.stringify({ data: [{ cve: "CVE-2024-1234", epss: String(epss), percentile: String(percentile), date: "2026-11-20" }] });
    const crear = (b, x = {}) => cve.crearExplotacion({ qRow: base(b), descargar: async () => assert.fail("no debía salir a la red"), habilitada: () => true, ...x });
    const HOY = new Date();
    test("🔴 lo que está en KEV es urgente y trae sus fechas", async () => {
      const r = await crear({ kev: { alta: "2024-02-01", vence: "2024-02-22", ransomware: 1 }, epss: { epss: "0.94000", percentil: "0.99900", fecha: "2026-11-20", actualizado: HOY } })("CVE-2024-1234", "low");
      assert.deepEqual(r, { kev: true, kev_desde: "2024-02-01", kev_vence: "2024-02-22", ransomware: true, epss: 0.94, epss_percentil: 0.999, epss_fecha: "2026-11-20", prioridad: "urgente" });
    });
    test("fuera de KEV, la prioridad sale de la severidad y el EPSS", async () => {
      for (const [sev, e, p] of [["critical", 0.6, "urgente"], ["critical", 0.01, "alta"], ["high", 0.2, "alta"], ["high", 0.01, "media"], ["low", 0.01, "baja"], ["medium", 0.7, "alta"]]) {
        const r = await crear({ epss: { epss: e, percentil: 0.5, fecha: "2026-11-20", actualizado: HOY } })("CVE-2024-1234", sev);
        assert.equal(r.kev, false); assert.equal(r.prioridad, p, `${sev} ${e}`);
      }
    });
    test("🔴 sin el catálogo descargado no dice que no está explotada", async () => {
      const r = await crear({ catalogo: 0, epss: { epss: 0.1, percentil: 0.5, fecha: null, actualizado: HOY } })("CVE-2024-1234", "high");
      assert.equal(r.kev, null); assert.match(r.avisos[0], /KEV/); assert.equal(r.prioridad_parcial, true);
    });
    test("🔴 un catálogo viejo tampoco permite decir que no está explotada, y lo que está en él sigue valiendo", async () => {
      for (const bajado of [new Date("2019-06-01"), null]) {
        const epss = { epss: 0.1, percentil: 0.5, fecha: null, actualizado: HOY };
        const r = await crear({ bajado, epss })("CVE-2024-1234", "high");
        assert.equal(r.kev, null); assert.match(r.avisos[0], /KEV/);
        assert.equal((await crear({ bajado, epss, kev: { alta: null, vence: null, ransomware: 1 } })("CVE-2024-1234", "high")).kev, true);
      }
    });
    test("🔴 CISA no confirma que no se use en ransomware: se informa desconocido", async () => {
      const r = await crear({ kev: { alta: null, vence: null, ransomware: 0 }, epss: { epss: 0.1, percentil: null, fecha: null, actualizado: HOY } })("CVE-2024-1234", "high");
      assert.equal(r.ransomware, null);
    });
    test("muchas consultas a la vez del mismo CVE hacen una sola descarga", async () => {
      let n = 0;
      const f = crear({}, { descargar: async () => { n++; await new Promise((ok) => setTimeout(ok, 30)); return first(0.3); } });
      const r = await Promise.all(Array.from({ length: 10 }, () => f("CVE-2024-1234", "high")));
      assert.equal(n, 1); assert.ok(r.every((x) => x.epss === 0.3));
    });
    test("🔴 si falta EPSS lo pide a FIRST, lo recuerda y no repite", async () => {
      let n = 0, url;
      const f = crear({}, { descargar: async (u) => { n++; url = u; return first(0.42); } });
      const r = await f("CVE-2024-1234", "high"); await f("CVE-2024-1234", "high");
      assert.equal(n, 1); assert.equal(r.epss, 0.42); assert.equal(r.epss_fecha, "2026-11-20"); assert.equal(r.prioridad, "alta");
      assert.match(url, /^https:\/\/api\.first\.org\/data\/v1\/epss\?cve=CVE-2024-1234$/);
    });
    test("🔴 sin red o apagado sigue respondiendo: EPSS desconocido, con aviso, sin insistir", async () => {
      let n = 0;
      const f = crear({}, { descargar: async () => { n++; throw new Error("sin red"); } });
      for (let i = 0; i < 3; i++) { const r = await f("CVE-2024-1234", "high"); assert.equal(r.epss, null); assert.match(r.avisos[0], /EPSS/); assert.equal(r.prioridad, "media"); }
      assert.equal(n, 1);
      const a = await crear({}, { habilitada: () => false })("CVE-2024-1234", "high");
      assert.equal(a.epss, null); assert.match(a.avisos[0], /EPSS/);
    });
    test("un EPSS guardado hace mucho se renueva, y si no se puede vale el guardado", async () => {
      const viejo = { epss: 0.2, percentil: 0.5, fecha: "2026-01-01", actualizado: new Date(Date.now() - 30 * 864e5) };
      assert.equal((await crear({ epss: viejo }, { descargar: async () => first(0.8) })("CVE-2024-1234", "high")).epss, 0.8);
      assert.equal((await crear({ epss: viejo }, { descargar: async () => { throw new Error("x"); } })("CVE-2024-1234", "high")).epss, 0.2);
    });
    test("🔴 un puntaje vacío no es cero", async () => {
      for (const v of ['""', "null"]) assert.equal((await crear({}, { descargar: async () => `{"data":[{"cve":"CVE-2024-1234","epss":${v},"percentile":"0.5"}]}` })("CVE-2024-1234", "high")).epss, null);
    });
    test("un CVE sin puntaje en FIRST no es un error, y sin severidad no se inventa prioridad", async () => {
      const r = await crear({}, { descargar: async () => '{"data":[]}' })("CVE-2024-1234", null);
      assert.equal(r.epss, null); assert.equal(r.prioridad, null); assert.equal(r.avisos, undefined); assert.equal(r.prioridad_parcial, undefined);
    });
    test("🔴 si la base falla, no se cae la consulta: se informa desconocido", async () => {
      const r = await crear({}, { qRow: async () => { throw new Error("db"); } })("CVE-2024-1234", "high");
      assert.equal(r.kev, null); assert.equal(r.epss, null); assert.ok(r.avisos.length >= 1);
    });
    test("KEV sin severidad es urgente igual", async () => {
      assert.equal((await crear({ kev: { alta: null, vence: null, ransomware: 0 }, epss: { epss: 0.1, percentil: null, fecha: null, actualizado: HOY } })("CVE-2024-1234", null)).prioridad, "urgente");
    });
  });
  test("traduce los errores de NVD", async () => {
    for (const [status, data, codigo] of [[429, "", 503], [403, "", 503], [500, "", 503], [404, "", 404], [200, '{"vulnerabilities":[]}', 404], [200, "<html>mantenimiento</html>", 503], [200, "{}", 503]])
      await assert.rejects(cve.crear({ pedir: async () => ({ status, data }) })("CVE-2024-1234"), (e) => e.codigo === codigo);
    await assert.rejects(cve.crear({ pedir: async () => { throw new Error("red"); } })("CVE-2024-1234"), (e) => e.codigo === 503);
  });
});
