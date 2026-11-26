/**
 * Secciones del engagement que escribe un agente: tiempo, fase activa, fases custom, resumen del informe y
 * cadena de ataque. El server.js real contra un MySQL o MariaDB de verdad, con su propio servidor.
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

const BACKEND = path.join(__dirname, "..");
const SECRETO = "pruebas-" + "0123456789abcdef".repeat(4);
const V1 = "/api/agente/v1";
const uid = () => crypto.randomUUID();
const hoy = () => new Date(Date.now() - 3 * 3600 * 1000).toISOString().slice(0, 10);

describe("secciones que escribe un agente", { skip: !URL_DB && "sin GUNGNIR_PRUEBA_DB" }, () => {
  let pool, hijo, base, salida = "";
  const suf = crypto.randomBytes(4).toString("hex");
  const U = Object.fromEntries(["admin", "pentester"].map((r) => [r, { id: uid(), role: r }]));
  const E = { a: uid(), custom: uid(), otro: uid() };
  const CLIENTE = uid();
  const keys = {};

  const token = (r) => jwt.sign({ id: U[r].id, role: r, tv: 0 }, SECRETO);
  const sql = async (q, p) => (await pool.query(q, p))[0];
  const fila = async (q, p) => (await sql(q, p))[0];
  async function pedir(metodo, ruta, bearer, body) {
    const h = { Authorization: `Bearer ${bearer}` };
    if (body !== undefined) h["Content-Type"] = "application/json";
    const r = await fetch(base + ruta, { method: metodo, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
    const texto = await r.text();
    let json = null; try { json = JSON.parse(texto); } catch {}
    return { status: r.status, texto, json };
  }
  const persona = (metodo, ruta, body) => pedir(metodo, `/api${ruta}`, token("admin"), body);
  const ag = (key, metodo, ruta, body) => pedir(metodo, V1 + ruta, keys[key], body);
  const aprobar = (id, datos) => persona("POST", `/agentes/propuestas/${id}/aprobar`, datos === undefined ? {} : { datos });
  async function hallazgo(e, extra = {}) {
    const id = uid();
    await sql("INSERT INTO findings (id,engagement_id,title,severity,affected_asset,status) VALUES (?,?,?,?,?,?)",
      [id, E[e], extra.title || `Hallazgo ${id.slice(0, 8)}`, extra.severity || "high", extra.affected_asset || "10.10.1.1", "open"]);
    return id;
  }

  before(async () => {
    const mysql = require("mysql2/promise");
    const u = new URL(URL_DB);
    const puerto = await new Promise((ok) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => ok(p)); }); });
    hijo = spawn(process.execPath, ["server.js"], {
      cwd: BACKEND,
      env: { ...process.env, PORT: String(puerto), NODE_ENV: "test", JWT_SECRET: SECRETO, TRUST_PROXY: "false", VULN_FUENTES_EXTERNAS: "0", AGENTE_LIMITE_15MIN: "5000",
             SMTP_HOST: "", DB_HOST: u.hostname, DB_PORT: u.port || "3306", DB_USER: decodeURIComponent(u.username), DB_PASSWORD: decodeURIComponent(u.password), DB_NAME: u.pathname.slice(1) },
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
      await sql("INSERT INTO users (id,username,email,password_hash,role,full_name) VALUES (?,?,?,?,?,?)", [x.id, `${x.role}-${suf}`, `${x.role}-${suf}@x`, "x", x.role, `Persona ${x.role}`]);
    await sql("INSERT INTO clients (id,name) VALUES (?,?)", [CLIENTE, "Cliente Ficticio"]);
    for (const [k, id] of Object.entries(E))
      await sql("INSERT INTO engagements (id,client_id,title,status,mode) VALUES (?,?,?,?,?)", [id, CLIENTE, `Prueba ${k}`, "planned", k === "custom" ? "custom" : "pentesting"]);
    for (const id of Object.values(E))
      for (const f of ["planning", "recon", "scanning", "exploitation", "post_exploitation", "reporting"])
        await sql("INSERT INTO phases (id,engagement_id,phase_type) VALUES (?,?,?)", [uid(), id, f]);
    for (const k of ["a", "custom", "otro"])
      assert.equal((await persona("PUT", `/agentes/engagements/${E[k]}`, { nivel_max: "total" })).status, 200);
    for (const [nombre, nivel] of [["escritura", "escritura"], ["propuesta", "propuesta"], ["lectura", "lectura"]]) {
      const r = await pedir("POST", "/api/agentes/keys", token("pentester"), { nombre: `${nombre}-${suf}`, nivel_max: nivel, engagements: [E.a, E.custom] });
      assert.equal(r.status, 201, r.texto);
      keys[nombre] = r.json.key;
    }
  });
  after(async () => {
    try {
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

  describe("tiempo", () => {
    test("🔴 con escritura carga la entrada a nombre del dueño de la key y el panel la suma", async () => {
      const r = await ag("escritura", "POST", `/engagements/${E.a}/tiempo`, { minutos: 90, fase: "recon", nota: "Enumeración DNS", fecha: "2026-11-20" });
      assert.equal(r.status, 201, r.texto);
      const t = await fila("SELECT * FROM time_entries WHERE id=?", [r.json.tiempo_id]);
      assert.equal(t.user_id, U.pentester.id);
      assert.equal(t.minutes, 90);
      assert.equal(t.phase_type, "recon");
      assert.equal(t.note, "Enumeración DNS");
      assert.equal(new Date(t.worked_on).toISOString().slice(0, 10), "2026-11-20");
      const p = await persona("GET", `/engagements/${E.a}/time`);
      assert.equal(p.json.resumen.por_fase.recon, 90);
    });
    test("sin fecha vale hoy", async () => {
      const r = await ag("escritura", "POST", `/engagements/${E.a}/tiempo`, { minutos: 15 });
      assert.equal(r.status, 201, r.texto);
      const t = await fila("SELECT DATE_FORMAT(worked_on,'%Y-%m-%d') AS d, phase_type FROM time_entries WHERE id=?", [r.json.tiempo_id]);
      assert.equal(t.d, hoy());
      assert.equal(t.phase_type, null);
    });
    test("🔴 en el nivel propuesta no se carga", async () => {
      const antes = await fila("SELECT COUNT(*) AS n FROM time_entries WHERE engagement_id=?", [E.a]);
      const r = await ag("propuesta", "POST", `/engagements/${E.a}/tiempo`, { minutos: 30 });
      assert.equal(r.status, 403);
      assert.equal(r.json.nivel_requerido, "escritura");
      assert.equal((await fila("SELECT COUNT(*) AS n FROM time_entries WHERE engagement_id=?", [E.a])).n, antes.n);
    });
    test("🔴 rechaza minutos fuera de rango, fechas futuras o inválidas y dos fases a la vez", async () => {
      const fc = uid();
      await sql("INSERT INTO custom_phases (id,engagement_id,name) VALUES (?,?,?)", [fc, E.custom, "Fase ajena"]);
      const casos = [
        [{ minutos: 0 }, 400, "minutos"], [{ minutos: 1441 }, 400, "minutos"], [{ minutos: 1.5 }, 400, "minutos"], [{}, 400, "minutos"],
        [{ minutos: 10, fecha: "2999-01-01" }, 400, "futura"], [{ minutos: 10, fecha: "2026-02-30" }, 400, "fecha"],
        [{ minutos: 10, fase: "recon", fase_custom: fc }, 400, "una sola"], [{ minutos: 10, fase: "lateral" }, 400, "fase"],
        [{ minutos: 10, fase_custom: fc }, 404, "fase custom"], [{ minutos: 10, extra: 1 }, 400, "no admitidos"],
      ];
      for (const [cuerpo, codigo, texto] of casos) {
        const r = await ag("escritura", "POST", `/engagements/${E.a}/tiempo`, cuerpo);
        assert.equal(r.status, codigo, `${JSON.stringify(cuerpo)}: ${r.texto}`);
        assert.match(r.json.error, new RegExp(texto, "i"), JSON.stringify(cuerpo));
      }
    });
    test("en un engagement custom se carga en una de sus fases", async () => {
      const fc = uid();
      await sql("INSERT INTO custom_phases (id,engagement_id,name) VALUES (?,?,?)", [fc, E.custom, "Relevamiento"]);
      const r = await ag("escritura", "POST", `/engagements/${E.custom}/tiempo`, { minutos: 45, fase_custom: fc });
      assert.equal(r.status, 201, r.texto);
      const p = await persona("GET", `/engagements/${E.custom}/time`);
      assert.equal(p.json.resumen.por_fase.Relevamiento, 45);
    });
  });

  describe("fase activa", () => {
    test("🔴 en el nivel propuesta queda a aprobar y no cambia nada hasta entonces", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.a}/fase`, { fase: "recon" });
      assert.equal(r.status, 202, r.texto);
      const e = await fila("SELECT current_phase, status FROM engagements WHERE id=?", [E.a]);
      assert.equal(e.current_phase, "planning");
      assert.equal(e.status, "planned");
      const dup = await ag("propuesta", "POST", `/engagements/${E.a}/fase`, { fase: "recon" });
      assert.equal(dup.status, 409, dup.texto);
      assert.equal(dup.json.existente.id, r.json.propuesta_id);

      const a = await aprobar(r.json.propuesta_id);
      assert.equal(a.status, 200, a.texto);
      const d = await fila("SELECT current_phase, status FROM engagements WHERE id=?", [E.a]);
      assert.equal(d.current_phase, "recon");
      assert.equal(d.status, "in_progress");
      assert.equal((await fila("SELECT status FROM phases WHERE engagement_id=? AND phase_type='recon'", [E.a])).status, "in_progress");
    });
    test("🔴 con escritura cambia la fase igual que el panel, y no marca en curso una fase terminada", async () => {
      await sql("UPDATE phases SET status='completed' WHERE engagement_id=? AND phase_type='scanning'", [E.a]);
      const r = await ag("escritura", "POST", `/engagements/${E.a}/fase`, { fase: "scanning" });
      assert.equal(r.status, 200, r.texto);
      assert.equal(r.json.fase, "scanning");
      assert.equal((await fila("SELECT current_phase FROM engagements WHERE id=?", [E.a])).current_phase, "scanning");
      assert.equal((await fila("SELECT status FROM phases WHERE engagement_id=? AND phase_type='scanning'", [E.a])).status, "completed");
    });
    test("🔴 la fase activa no se vuelve a pedir, y una fase inexistente se rechaza", async () => {
      const r = await ag("escritura", "POST", `/engagements/${E.a}/fase`, { fase: "scanning" });
      assert.equal(r.status, 409, r.texto);
      assert.equal((await ag("escritura", "POST", `/engagements/${E.a}/fase`, { fase: "lateral" })).status, 400);
      assert.equal((await ag("lectura", "POST", `/engagements/${E.a}/fase`, { fase: "recon" })).status, 403);
    });
    test("al aprobar, la persona puede elegir otra fase", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.a}/fase`, { fase: "exploitation" });
      assert.equal(r.status, 202, r.texto);
      const a = await aprobar(r.json.propuesta_id, { fase: "post_exploitation" });
      assert.equal(a.status, 200, a.texto);
      assert.equal((await fila("SELECT current_phase FROM engagements WHERE id=?", [E.a])).current_phase, "post_exploitation");
    });
    test("el cambio de fase del panel sigue igual", async () => {
      const r = await persona("PUT", `/engagements/${E.otro}/phase`, { phase: "exploitation" });
      assert.equal(r.status, 200, r.texto);
      assert.deepEqual(r.json, { ok: true, current_phase: "exploitation" });
      const e = await fila("SELECT current_phase, status FROM engagements WHERE id=?", [E.otro]);
      assert.equal(e.current_phase, "exploitation");
      assert.equal(e.status, "in_progress");
      assert.equal((await persona("PUT", `/engagements/${E.otro}/phase`, { phase: "lateral" })).status, 400);
    });
  });

  describe("fases custom", () => {
    let fc;
    before(async () => {
      fc = uid();
      await sql("INSERT INTO custom_phases (id,engagement_id,name,description,work_plan,order_index) VALUES (?,?,?,?,?,?)", [fc, E.custom, "Revisión de código", "Repositorio principal", "Plan de la persona", 0]);
    });
    test("🔴 ver_engagement lista las fases custom con su plan y su estado", async () => {
      const r = await ag("lectura", "GET", `/engagements/${E.custom}`);
      assert.equal(r.status, 200, r.texto);
      const f = r.json.datos.fases_custom.find((x) => x.id === fc);
      assert.deepEqual(f, { id: fc, nombre: "Revisión de código", descripcion: "Repositorio principal", estado: "not_started", plan: "Plan de la persona" });
      assert.equal((await ag("lectura", "GET", `/engagements/${E.a}`)).json.datos.fases_custom, undefined);
    });
    test("🔴 con escritura cambia el plan y el estado", async () => {
      const r = await ag("escritura", "PUT", `/engagements/${E.custom}/fases-custom/${fc}`, { plan: "1. Dependencias\n2. Secretos", estado: "in_progress" });
      assert.equal(r.status, 200, r.texto);
      const f = await fila("SELECT work_plan, status FROM custom_phases WHERE id=?", [fc]);
      assert.deepEqual({ ...f }, { work_plan: "1. Dependencias\n2. Secretos", status: "in_progress" });
      const solo = await ag("escritura", "PUT", `/engagements/${E.custom}/fases-custom/${fc}`, { estado: "completed" });
      assert.equal(solo.status, 200, solo.texto);
      assert.equal((await fila("SELECT work_plan FROM custom_phases WHERE id=?", [fc])).work_plan, "1. Dependencias\n2. Secretos");
    });
    test("🔴 rechaza un pedido vacío, un estado raro y una fase de otro engagement", async () => {
      assert.equal((await ag("escritura", "PUT", `/engagements/${E.custom}/fases-custom/${fc}`, {})).status, 400);
      assert.equal((await ag("escritura", "PUT", `/engagements/${E.custom}/fases-custom/${fc}`, { estado: "pausada" })).status, 400);
      assert.equal((await ag("escritura", "PUT", `/engagements/${E.a}/fases-custom/${fc}`, { estado: "completed" })).status, 404);
      assert.equal((await ag("lectura", "PUT", `/engagements/${E.custom}/fases-custom/${fc}`, { estado: "completed" })).status, 403);
    });
    test("🔴 en el nivel propuesta queda a aprobar; si la persona cambió el plan, avisa", async () => {
      const r = await ag("propuesta", "PUT", `/engagements/${E.custom}/fases-custom/${fc}`, { plan: "Plan del agente" });
      assert.equal(r.status, 202, r.texto);
      assert.equal((await fila("SELECT work_plan FROM custom_phases WHERE id=?", [fc])).work_plan, "1. Dependencias\n2. Secretos");
      const dup = await ag("propuesta", "PUT", `/engagements/${E.custom}/fases-custom/${fc}`, { estado: "completed" });
      assert.equal(dup.status, 409, dup.texto);
      const det = await persona("GET", `/agentes/propuestas/${r.json.propuesta_id}`);
      assert.equal(det.json.actual.plan, "1. Dependencias\n2. Secretos");
      assert.equal(det.json.datos.fase_nombre, "Revisión de código");
      assert.equal(det.json.cambio, false);

      await persona("PUT", `/engagements/${E.custom}/custom-phases/${fc}`, { work_plan: "Lo reescribió la persona" });
      const choque = await aprobar(r.json.propuesta_id);
      assert.equal(choque.status, 409, choque.texto);
      assert.equal(choque.json.conflicto, true);
      const forzada = await persona("POST", `/agentes/propuestas/${r.json.propuesta_id}/aprobar`, { forzar: true, datos: { plan: "Plan corregido" } });
      assert.equal(forzada.status, 200, forzada.texto);
      assert.equal((await fila("SELECT work_plan FROM custom_phases WHERE id=?", [fc])).work_plan, "Plan corregido");
    });
    test("🔴 las actualizaciones son registro: se publican desde el nivel propuesta y el panel las muestra", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.custom}/fases-custom/${fc}/actualizaciones`, { contenido: "Se revisaron 40 dependencias." });
      assert.equal(r.status, 201, r.texto);
      const p = await persona("GET", `/engagements/${E.custom}/custom-phases/${fc}/updates`);
      assert.equal(p.json[0].content, "Se revisaron 40 dependencias.");
      assert.equal(p.json[0].created_by, U.pentester.id);
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.custom}/fases-custom/${fc}/actualizaciones`, { contenido: " " })).status, 400);
      assert.equal((await ag("lectura", "POST", `/engagements/${E.custom}/fases-custom/${fc}/actualizaciones`, { contenido: "x" })).status, 403);
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.a}/fases-custom/${fc}/actualizaciones`, { contenido: "x" })).status, 404);
    });
  });
});
