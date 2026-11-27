/**
 * Módulos de Gungnir que el agente lee o usa: vulnerabilidades, tiempo, Navigator, remediación, notas,
 * documentos de fases custom, recon, Exploit-DB y papers. El server.js real contra un MySQL o MariaDB de
 * verdad, con su propio servidor. Nada de esto sale a internet: lo que consultaría afuera se prueba en lo
 * que rechaza antes.
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
const { ocultarClaves, ipsAConsultar } = require("../integrations/recon");
const URL_DB = process.env.GUNGNIR_PRUEBA_DB;

const BACKEND = path.join(__dirname, "..");
const SECRETO = "pruebas-" + "0123456789abcdef".repeat(4);
const V1 = "/api/agente/v1";
const uid = () => crypto.randomUUID();

test("las keys del recon no salen en el resultado, ni dentro de un error que cita la URL", () => {
  const r = ocultarClaves({ shodan: { ok: false, error: "GET https://api.shodan.io/x?key=ABCD1234secreto falló" }, dns: { a: ["10.0.0.1"] } }, { shodan: "ABCD1234secreto" });
  assert.equal(r.shodan.error, "GET https://api.shodan.io/x?key=[OCULTO] falló");
  assert.deepEqual(r.dns, { a: ["10.0.0.1"] });
  assert.deepEqual(ocultarClaves({ x: 1 }, {}), { x: 1 });
});

test("a Shodan solo se le pregunta por las IPs del dominio que se permiten, sin repetir", () => {
  const dentro = (ip) => ip.startsWith("10.");
  assert.deepEqual(ipsAConsultar("10.0.0.1", ["10.0.0.1", "10.0.0.2"]), ["10.0.0.1"]);
  assert.deepEqual(ipsAConsultar("172.16.0.1", ["10.0.0.2"], dentro), ["10.0.0.2"]);
  assert.deepEqual(ipsAConsultar("172.16.0.1", ["172.16.0.2"], dentro), []);
  assert.deepEqual(ipsAConsultar(null, [], dentro), []);
});

describe("conexiones del agente con el resto de Gungnir", { skip: !URL_DB && "sin GUNGNIR_PRUEBA_DB" }, () => {
  let pool, hijo, base, salida = "";
  // La carpeta de subidas del server.js: lo que se sube acá se borra al terminar.
  const uploads = path.join(BACKEND, "..", "uploads");
  const subidos = [];
  const suf = crypto.randomBytes(4).toString("hex");
  const U = Object.fromEntries(["admin", "pentester"].map((r) => [r, { id: uid(), role: r }]));
  const E = { a: uid(), custom: uid() };
  const CLIENTE = uid(), OTRO_CLIENTE = uid();
  const FASE = uid(), ACT = uid();
  const keys = {};

  const token = (r) => jwt.sign({ id: U[r].id, role: r, tv: 0 }, SECRETO);
  const sql = async (q, p) => (await pool.query(q, p))[0];
  const fila = async (q, p) => (await sql(q, p))[0];
  async function pedir(metodo, ruta, bearer, body) {
    const h = { Authorization: `Bearer ${bearer}` };
    let cuerpo;
    if (body instanceof FormData) cuerpo = body;
    else if (body !== undefined) { h["Content-Type"] = "application/json"; cuerpo = JSON.stringify(body); }
    const r = await fetch(base + ruta, { method: metodo, headers: h, body: cuerpo });
    const texto = await r.text();
    let json = null; try { json = JSON.parse(texto); } catch {}
    return { status: r.status, texto, json };
  }
  const persona = (metodo, ruta, body) => pedir(metodo, `/api${ruta}`, token("admin"), body);
  const ag = (key, metodo, ruta, body) => pedir(metodo, V1 + ruta, keys[key], body);
  const archivo = (nombre, contenido, extra = {}) => {
    const f = new FormData();
    f.append("archivo", new Blob([contenido]), nombre);
    for (const [k, v] of Object.entries(extra)) f.append(k, v);
    return f;
  };

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
    for (const c of [CLIENTE, OTRO_CLIENTE]) await sql("INSERT INTO clients (id,name) VALUES (?,?)", [c, `Cliente ${c.slice(0, 6)}`]);
    for (const [k, id] of Object.entries(E))
      await sql("INSERT INTO engagements (id,client_id,title,status,mode) VALUES (?,?,?,?,?)", [id, CLIENTE, `Prueba ${k}`, "in_progress", k === "custom" ? "custom" : "pentesting"]);
    for (const [t, v, d] of [["ip", "10.10.1.5", 1], ["ip", "10.10.1.6", 1], ["domain", "app.ejemplo.test", 1], ["domain", "admin.ejemplo.test", 0]])
      await sql("INSERT INTO scope_items (id,engagement_id,type,value,in_scope) VALUES (?,?,?,?,?)", [uid(), E.a, t, v, d]);
    await sql("INSERT INTO custom_phases (id,engagement_id,name) VALUES (?,?,?)", [FASE, E.custom, "Revisión de código"]);
    await sql("INSERT INTO custom_phase_updates (id,phase_id,content,created_by) VALUES (?,?,?,?)", [ACT, FASE, "Primer avance", U.admin.id]);
    for (const k of ["a", "custom"])
      assert.equal((await persona("PUT", `/agentes/engagements/${E[k]}`, { nivel_max: "total" })).status, 200);
    for (const nivel of ["escritura", "propuesta", "lectura"]) {
      const r = await pedir("POST", "/api/agentes/keys", token("pentester"), { nombre: `${nivel}-${suf}`, nivel_max: nivel, engagements: [E.a, E.custom] });
      assert.equal(r.status, 201, r.texto);
      keys[nivel] = r.json.key;
    }
  });
  after(async () => {
    try {
      if (pool) {
        await sql("DELETE FROM vuln_hallazgos WHERE cliente_id IN (?)", [[CLIENTE, OTRO_CLIENTE]]);
        await sql("DELETE FROM activos WHERE tenant_id IN (?)", [[CLIENTE, OTRO_CLIENTE]]);
        await sql("DELETE FROM papers WHERE user_id IN (?)", [Object.values(U).map((x) => x.id)]);
        await sql("DELETE FROM engagements WHERE client_id=?", [CLIENTE]);
        await sql("DELETE FROM clients WHERE id IN (?)", [[CLIENTE, OTRO_CLIENTE]]);
        await sql("DELETE FROM users WHERE id IN (?)", [Object.values(U).map((x) => x.id)]);
      }
    } finally {
      if (pool) await pool.end();
      if (hijo && hijo.exitCode === null) await new Promise((ok) => { hijo.on("exit", ok); hijo.kill("SIGKILL"); });
      for (const f of subidos) fs.rmSync(path.join(uploads, f), { force: true });
    }
  });

  describe("vulnerabilidades", () => {
    test("🔴 ve solo las del cliente del engagement y de activos en alcance, y marca las que ya trajo", async () => {
      const activo = async (cliente, ip, hostname) => {
        const id = uid();
        await sql("INSERT INTO activos (id,tenant_id,nombre,ip,hostname) VALUES (?,?,?,?,?)", [id, cliente, `Equipo ${ip}`, ip, hostname]);
        return id;
      };
      const vuln = async (cliente, act, titulo, extra = {}) => {
        const id = uid();
        await sql("INSERT INTO vuln_hallazgos (id,cliente_id,activo_id,fuente,titulo,severidad,clave_dedup,estado,engagement_id,finding_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
          [id, cliente, act, "nessus", titulo, extra.severidad || "high", crypto.randomBytes(32).toString("hex"), "abierto", extra.engagement_id || null, extra.finding_id || null]);
        return id;
      };
      const dentro = await activo(CLIENTE, "10.10.1.5", null);
      const porNombre = await activo(CLIENTE, "192.168.9.9", "app.ejemplo.test");
      const excluido = await activo(CLIENTE, "10.10.1.6", "admin.ejemplo.test");
      const fuera = await activo(CLIENTE, "172.16.0.1", null);
      const ajeno = await activo(OTRO_CLIENTE, "10.10.1.5", null);
      const fa = uid(), fc = uid();
      await sql("INSERT INTO findings (id,engagement_id,title,severity,affected_asset,status) VALUES (?,?,?,?,?,?),(?,?,?,?,?,?)",
        [fa, E.a, "OpenSSH viejo", "high", "10.10.1.5", "open", fc, E.custom, "Llevada a otro", "low", "10.10.1.5", "open"]);
      const v1 = await vuln(CLIENTE, dentro, "OpenSSH viejo", { engagement_id: E.a, finding_id: fa });
      const v3 = await vuln(CLIENTE, dentro, "Llevada a otro", { engagement_id: E.custom, finding_id: fc, severidad: "low" });
      const v2 = await vuln(CLIENTE, porNombre, "TLS 1.0", { severidad: "medium" });
      await vuln(CLIENTE, excluido, "Panel expuesto");
      await vuln(CLIENTE, fuera, "SMB firmado opcional");
      await vuln(OTRO_CLIENTE, ajeno, "De otro cliente");

      const r = await ag("lectura", "GET", `/engagements/${E.a}/vulnerabilidades`);
      assert.equal(r.status, 200, r.texto);
      assert.equal(r.json.contenido_no_confiable, true);
      assert.deepEqual(r.json.datos.map((v) => v.id).sort(), [v1, v2, v3].sort());
      const de = (id) => r.json.datos.find((v) => v.id === id);
      assert.deepEqual([de(v1).ya_en_este_engagement, de(v1).ya_en_otro_engagement, de(v1).finding_id], [true, false, fa]);
      assert.deepEqual([de(v2).ya_en_este_engagement, de(v2).ya_en_otro_engagement], [false, false]);
      // El hallazgo de otro engagement no se nombra: solo se dice que ya se trajo.
      assert.deepEqual([de(v3).ya_en_este_engagement, de(v3).ya_en_otro_engagement, de(v3).finding_id], [false, true, undefined]);

      const filtrado = await ag("lectura", "GET", `/engagements/${E.a}/vulnerabilidades?severidad=medium`);
      assert.deepEqual(filtrado.json.datos.map((v) => v.id), [v2]);
      assert.equal((await ag("lectura", "GET", `/engagements/${E.a}/vulnerabilidades?estado=cerrada`)).status, 400);
    });
  });

  describe("tiempo, Navigator y remediación", () => {
    test("🔴 lista el tiempo cargado con los totales, y marca lo del dueño de la key", async () => {
      await sql("INSERT INTO time_entries (id,engagement_id,phase_type,user_id,minutes,note,worked_on) VALUES (?,?,?,?,?,?,?),(?,?,?,?,?,?,?)",
        [uid(), E.a, "recon", U.pentester.id, 60, "DNS", "2026-11-20", uid(), E.a, "scanning", U.admin.id, 30, null, "2026-11-21"]);
      const r = await ag("lectura", "GET", `/engagements/${E.a}/tiempo`);
      assert.equal(r.status, 200, r.texto);
      assert.equal(r.json.resumen.total_minutes, 90);
      assert.deepEqual(r.json.resumen.por_fase, { recon: 60, scanning: 30 });
      assert.deepEqual(r.json.datos.map((t) => [t.worked_on, t.minutes, t.mio]), [["2026-11-21", 30, false], ["2026-11-20", 60, true]]);
      const panel = await persona("GET", `/engagements/${E.a}/time`);
      assert.equal(panel.json.resumen.total_minutes, 90);
      assert.equal(panel.json.entries.length, 2);
    });

    test("🔴 la capa de Navigator lleva cada técnica con id una vez, y el export del panel ya no falla", async () => {
      await sql("INSERT INTO engagement_techniques (id,engagement_id,phase_type,mitre_id,name,added_at) VALUES (?,?,?,?,?,?),(?,?,?,?,?,?),(?,?,?,?,?,?)",
        [uid(), E.a, "recon", "t1190", "Repetida, registrada después", "2026-11-21 10:00:00", uid(), E.a, "exploitation", "T1190", "Exploit Public-Facing Application", "2026-11-20 10:00:00",
         uid(), E.a, "recon", null, "Sin id", "2026-11-19 10:00:00"]);
      const r = await ag("lectura", "GET", `/engagements/${E.a}/navigator`);
      assert.equal(r.status, 200, r.texto);
      assert.equal(r.json.datos.name, "Gungnir - Prueba a");
      assert.deepEqual(r.json.datos.techniques.map((t) => [t.techniqueID, t.color]), [["T1190", "#e8192c"]]);
      const panel = await persona("GET", `/engagements/${E.a}/attack-navigator.json`);
      assert.equal(panel.status, 200, panel.texto);
      assert.deepEqual(panel.json, r.json.datos);
    });

    test("🔴 ver_engagement trae la remediación, igual que el resumen del panel", async () => {
      await sql("INSERT INTO findings (id,engagement_id,title,severity,initial_severity,affected_asset,status,retest_status,retest_severity,remediation_due_date) VALUES (?,?,?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?,?,?)",
        [uid(), E.a, "Vencido", "high", "high", "10.10.1.5", "open", "not_retested", null, "2020-01-01",
         uid(), E.a, "Bajó", "high", "critical", "10.10.1.5", "in_remediation", "partial", "medium", null]);
      const r = await ag("lectura", "GET", `/engagements/${E.a}`);
      assert.equal(r.status, 200, r.texto);
      const rem = r.json.datos.remediacion;
      // Las pruebas de vulnerabilidades también dejan un hallazgo sin retest en este engagement.
      const sinRetest = (await fila("SELECT COUNT(*) AS n FROM findings WHERE engagement_id=? AND retest_status='not_retested'", [E.a])).n;
      assert.equal(rem.total, sinRetest + 1);
      assert.equal(rem.vencidos, 1);
      assert.deepEqual(rem.por_retest, { not_retested: sinRetest, passed: 0, failed: 0, partial: 1 });
      assert.deepEqual(rem.diffs.map((d) => [d.title, d.de, d.a]), [["Bajó", "critical", "medium"]]);
      const panel = await persona("GET", `/engagements/${E.a}/remediation-summary`);
      assert.deepEqual({ ...panel.json, diffs: panel.json.diffs.map((d) => d.id).sort() }, { ...rem, diffs: rem.diffs.map((d) => d.id).sort() });
    });
  });

  describe("notas", () => {
    test("🔴 ve solo las notas propias del dueño de la key en este engagement, nunca las compartidas", async () => {
      const nota = async (usuario, engagement, titulo) => {
        const id = uid();
        await sql("INSERT INTO notes (id,user_id,title,content,tags,engagement_id) VALUES (?,?,?,?,?,?)", [id, usuario, titulo, `Contenido ${titulo}`, '["x"]', engagement]);
        return id;
      };
      const propia = await nota(U.pentester.id, E.a, "Propia");
      await nota(U.pentester.id, E.custom, "De otro engagement");
      await nota(U.pentester.id, null, "Sin engagement");
      const compartida = await nota(U.admin.id, E.a, "Compartida por otra persona");
      await sql("INSERT INTO note_shares (note_id,user_id) VALUES (?,?)", [compartida, U.pentester.id]);
      const r = await ag("lectura", "GET", `/engagements/${E.a}/notas`);
      assert.equal(r.status, 200, r.texto);
      assert.deepEqual(r.json.datos.map((n) => n.id), [propia]);
      assert.deepEqual(r.json.datos[0].tags, ["x"]);
      assert.equal((await ag("lectura", "GET", `/engagements/${E.a}/notas/${compartida}`)).status, 404);
      assert.equal((await ag("lectura", "GET", `/engagements/${E.a}/notas/${propia}`)).json.datos.content, "Contenido Propia");
    });

    test("🔴 crea la nota en la libreta del dueño de la key, vinculada al engagement; con lectura no", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.a}/notas`, { titulo: "Pista", contenido: "Revisar el backup de las 3 AM", etiquetas: ["backup", "backup"] });
      assert.equal(r.status, 201, r.texto);
      const n = await fila("SELECT * FROM notes WHERE id=?", [r.json.nota_id]);
      assert.equal(n.user_id, U.pentester.id);
      assert.equal(n.engagement_id, E.a);
      assert.equal(n.content, "Revisar el backup de las 3 AM");
      assert.deepEqual(typeof n.tags === "string" ? JSON.parse(n.tags) : n.tags, ["backup"]);
      assert.equal((await fila("SELECT accion FROM agente_actividad WHERE engagement_id=? AND accion='nota' LIMIT 1", [E.a]))?.accion, "nota");
      assert.equal((await ag("lectura", "POST", `/engagements/${E.a}/notas`, { titulo: "No" })).status, 403);
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.a}/notas`, { contenido: "Sin título" })).status, 400);
    });
  });

  describe("documentos e imágenes de fases custom", () => {
    test("🔴 sube un documento a la fase, el panel lo descarga y el agente lo lista sin contenido", async () => {
      const r = await ag("propuesta", "POST", `/engagements/${E.custom}/fases-custom/${FASE}/documentos`, archivo("hallazgos.md", "# Notas de la revisión", { descripcion: "Resumen" }));
      assert.equal(r.status, 201, r.texto);
      const d = await fila("SELECT * FROM custom_phase_docs WHERE id=?", [r.json.documento_id]);
      subidos.push(d.filename);
      assert.equal(d.phase_id, FASE);
      assert.equal(d.engagement_id, E.custom);
      assert.equal(d.caption, "Resumen");
      assert.equal(d.uploaded_by, U.pentester.id);
      assert.equal(fs.readFileSync(path.join(uploads, d.filename), "utf8"), "# Notas de la revisión");
      const descarga = await persona("GET", `/engagements/${E.custom}/custom-phases/${FASE}/documents/${d.id}/download`);
      assert.equal(descarga.texto, "# Notas de la revisión");
      const lista = await ag("lectura", "GET", `/engagements/${E.custom}/documentos`);
      assert.deepEqual(lista.json.datos.map((x) => [x.tipo, x.original_name, x.fase_custom]), [["documento", "hallazgos.md", FASE]]);
      for (const nombre of ["x.html", "x.svg", "a.png.html"])
        assert.equal((await ag("propuesta", "POST", `/engagements/${E.custom}/fases-custom/${FASE}/documentos`, archivo(nombre, "<script>"))).status, 400, nombre);
      // El nombre que manda el agente queda solo como nombre original: el archivo va con uno al azar dentro de uploads.
      const raro = await ag("propuesta", "POST", `/engagements/${E.custom}/fases-custom/${FASE}/documentos`, archivo("../../fuera.md", "x"));
      assert.equal(raro.status, 201, raro.texto);
      const dr = await fila("SELECT original_name, filename FROM custom_phase_docs WHERE id=?", [raro.json.documento_id]);
      subidos.push(dr.filename);
      assert.equal(dr.original_name, "fuera.md");
      assert.match(dr.filename, /^[0-9a-f]{32}$/);
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.a}/fases-custom/${FASE}/documentos`, archivo("a.md", "x"))).status, 404);
    });

    test("🔴 una imagen va a una actualización de la fase; otro tipo de archivo se rechaza", async () => {
      const ruta = `/engagements/${E.custom}/fases-custom/${FASE}/actualizaciones/${ACT}/imagenes`;
      assert.equal((await ag("propuesta", "POST", ruta, archivo("notas.txt", "texto"))).status, 400);
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.custom}/fases-custom/${FASE}/actualizaciones/${uid()}/imagenes`, archivo("a.png", "png"))).status, 404);
      // Una actualización de otra fase del mismo engagement tampoco sirve.
      const otraFase = uid(), otraAct = uid();
      await sql("INSERT INTO custom_phases (id,engagement_id,name) VALUES (?,?,?)", [otraFase, E.custom, "Otra fase"]);
      await sql("INSERT INTO custom_phase_updates (id,phase_id,content,created_by) VALUES (?,?,?,?)", [otraAct, otraFase, "Otro avance", U.admin.id]);
      assert.equal((await ag("propuesta", "POST", `/engagements/${E.custom}/fases-custom/${FASE}/actualizaciones/${otraAct}/imagenes`, archivo("a.png", "png"))).status, 404);
      assert.equal((await ag("lectura", "POST", ruta, archivo("a.png", "png"))).status, 403);
      const r = await ag("propuesta", "POST", ruta, archivo("captura.png", "\x89PNG"));
      assert.equal(r.status, 201, r.texto);
      const i = await fila("SELECT * FROM custom_phase_update_images WHERE id=?", [r.json.imagen_id]);
      subidos.push(i.filename);
      assert.equal(i.update_id, ACT);
      assert.ok(fs.existsSync(path.join(uploads, i.filename)));
      const lista = await ag("lectura", "GET", `/engagements/${E.custom}/documentos`);
      assert.deepEqual(lista.json.datos.find((x) => x.tipo === "imagen")?.actualizacion_id, ACT);
    });
  });

  describe("recon, Exploit-DB y papers", () => {
    test("🔴 el recon de un objetivo fuera de alcance se rechaza sin consultar a nadie", async () => {
      const r = await ag("lectura", "POST", `/engagements/${E.a}/recon`, { objetivo: "172.16.0.1" });
      assert.equal(r.status, 422, r.texto);
      assert.match(r.json.error, /No se consultó/);
      assert.equal((await ag("lectura", "POST", `/engagements/${E.a}/recon`, { objetivo: "admin.ejemplo.test" })).status, 422);
      assert.equal((await ag("lectura", "POST", `/engagements/${E.a}/recon`, {})).status, 400);
    });

    test("🔴 el recon solo acepta una IP o un dominio: una URL, un puerto o un usuario no se consultan", async () => {
      for (const objetivo of ["https://app.ejemplo.test/", "app.ejemplo.test:443", "10.10.1.5:22", "*.ejemplo.test"]) {
        const r = await ag("lectura", "POST", `/engagements/${E.a}/recon`, { objetivo });
        assert.equal(r.status, 400, `${objetivo}: ${r.texto}`);
        assert.match(r.json.error, /una sola IP o un dominio/);
      }
      assert.equal((await fila("SELECT COUNT(*) AS n FROM audit_logs WHERE action='agente_recon' AND entity_id=?", [E.a])).n, 0);
    });

    test("🔴 Exploit-DB pide al menos 2 caracteres antes de salir", async () => {
      assert.equal((await ag("lectura", "GET", "/exploitdb?q=a")).status, 400);
      assert.equal((await ag("lectura", "GET", "/exploitdb")).status, 400);
    });

    test("🔴 los papers son los del dueño de la key: los de otra persona no aparecen ni se abren", async () => {
      const propio = uid(), ajeno = uid();
      await sql("INSERT INTO papers (id,user_id,title,cve_id) VALUES (?,?,?,?),(?,?,?,?)", [propio, U.pentester.id, "Desbordamiento en el parser", "CVE-2026-1234", ajeno, U.admin.id, "Paper ajeno", null]);
      const r = await ag("lectura", "GET", "/papers");
      assert.equal(r.status, 200, r.texto);
      assert.deepEqual(r.json.datos.map((p) => p.id), [propio]);
      assert.deepEqual((await ag("lectura", "GET", "/papers?q=CVE-2026-1234")).json.datos.map((p) => p.id), [propio]);
      const uno = await ag("lectura", "GET", `/papers/${propio}`);
      assert.equal(uno.json.datos.title, "Desbordamiento en el parser");
      assert.equal(uno.json.datos.user_id, undefined);
      assert.equal((await ag("lectura", "GET", `/papers/${ajeno}`)).status, 404);
    });
  });
});
