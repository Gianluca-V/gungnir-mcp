// Núcleo de los agentes: niveles de autonomía, alcance y ocultamiento de datos. Sin base ni red.
"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const N = require("../agentes/niveles");
const { evaluar } = require("../agentes/alcance");
const O = require("../agentes/ocultar");
const acceso = require("../agentes/acceso");

describe("niveles de autonomía", () => {
  test("vale el más restrictivo entre la key y el engagement", () => {
    assert.equal(N.efectivo("total", "propuesta"), "propuesta");
    assert.equal(N.efectivo("lectura", "total"), "lectura");
    assert.equal(N.efectivo("total", "total"), "total");
  });
  test("lo que falta o no se reconoce no da acceso", () => {
    for (const v of [undefined, null, "", "admin", "TOTAL", "__proto__"]) assert.equal(N.efectivo("total", v), "ninguno");
  });
  test("cada nivel alcanza a los de abajo y no a los de arriba", () => {
    assert.ok(N.alcanza("escritura", "propuesta"));
    assert.ok(!N.alcanza("escritura", "total"));
    assert.ok(!N.alcanza("ninguno", "lectura"));
    assert.ok(!N.alcanza("total", "inventado"));
  });
  test("el rol del dueño pone techo: un lector nunca escribe y un rol desconocido no entra", () => {
    assert.equal(N.techoDeRol("lector"), "lectura");
    assert.equal(N.techoDeRol("pentester"), "total");
    assert.equal(N.techoDeRol("otro"), "ninguno");
  });
  test("un engagement entregado o archivado queda en lectura", () => {
    assert.equal(N.techoDeEstado("archived"), "lectura");
    assert.equal(N.techoDeEstado("delivered"), "lectura");
    assert.equal(N.techoDeEstado("in_progress"), "total");
  });
});

describe("alcance", () => {
  const en = (type, value) => ({ type, value, in_scope: 1 });
  const fuera = (type, value) => ({ type, value, in_scope: 0 });
  const ALCANCE = [
    en("cidr", "10.10.0.0/16"), fuera("ip", "10.10.5.5"), fuera("cidr", "10.10.9.0/24"),
    en("domain", "app.ejemplo.com"), en("domain", "*.lab.ejemplo.com"), fuera("domain", "prod.lab.ejemplo.com"),
    en("url", "https://portal.ejemplo.com/app"), en("ip", "2001:db8::/32"), en("application", "App móvil"),
  ];
  const casos = [
    ["10.10.1.1", true], ["10.10.1.1:8080", true], ["10.10.1.1:445/tcp", true], ["10.11.0.1", false],
    ["10.10.5.5", false], ["10.10.9.0/25", false], ["10.10.0.0/16", false], ["10.10.1.0/24", true],
    ["10.0.0.0/8", false], ["0.0.0.0/0", false], ["10.10.1.1-20", true], ["10.10.5.1-20", false],
    ["168427777", false], ["0x0a0a0101", false], ["010.10.1.1", false],
    ["app.ejemplo.com", true], ["APP.ejemplo.com.", true], ["ejemplo.com", false], ["x.app.ejemplo.com", false],
    ["app.ejemplo.com.atacante.net", false], ["noapp.ejemplo.com", false],
    ["a.lab.ejemplo.com", true], ["lab.ejemplo.com", false], ["prod.lab.ejemplo.com", false],
    ["https://app.ejemplo.com/cualquier/ruta?x=1", true], ["https://app.ejemplo.com@malo.net/", false],
    ["https://portal.ejemplo.com/app/login", true], ["https://portal.ejemplo.com/app", true],
    ["https://portal.ejemplo.com/aplicacion", false], ["https://portal.ejemplo.com/app/../admin", false],
    ["https://portal.ejemplo.com/app/%2e%2e/admin", false], ["portal.ejemplo.com", false], ["http://portal.ejemplo.com/app", false],
    ["2001:db8::1", true], ["[2001:db8::1]:443", true], ["2001:db9::1", false], ["::ffff:10.10.1.1", true], ["::ffff:10.10.5.5", false],
    ["App móvil", true], ["app MÓVIL", true], ["", false], ["   ", false], ["$(id)", false],
    ["10.10.1.1, 10.10.1.2", true], ["10.10.1.1, 8.8.8.8", false], ["10.10.1.1 8.8.8.8", false],
  ];
  for (const [objetivo, dentro] of casos)
    test(`${JSON.stringify(objetivo)} ${dentro ? "está dentro" : "queda fuera"}`, () => {
      const r = evaluar(objetivo, ALCANCE);
      assert.equal(r.dentro, dentro, JSON.stringify(r));
      if (!dentro) assert.ok(r.motivo);
    });
  test("sin alcance cargado, todo queda fuera", () => {
    assert.equal(evaluar("10.10.1.1", []).dentro, false);
  });
  test("un ítem de alcance ilegible no habilita nada", () => {
    assert.equal(evaluar("8.8.8.8", [en("cidr", "10.0.0.0/99"), en("cidr", "cualquiera"), en("domain", "*")]).dentro, false);
  });
  test("una exclusión ilegible hace que nada quede dentro: no se sabe qué excluye", () => {
    assert.equal(evaluar("10.10.1.1", [en("cidr", "10.10.0.0/16"), fuera("cidr", "10.10.0.0/99")]).dentro, false);
  });
  test("una dirección escrita en un ítem domain también vale como IP", () => {
    assert.equal(evaluar("192.168.1.4", [en("domain", "192.168.1.4")]).dentro, true);
  });
  // Hallazgos de la verificación independiente.
  const dentro = (objetivo, ...items) => evaluar(objetivo, items).dentro;
  const RED = en("cidr", "10.0.0.0/24"), SITIO = en("domain", "app.acme.com");
  describe("una exclusión con puerto alcanza a lo que no lo indica", () => {
    for (const [o, d] of [["10.0.0.5", false], ["10.0.0.0/24", false], ["ssh://10.0.0.5/", false], ["sftp://10.0.0.5/", false], ["raro://10.0.0.5/", false], ["10.0.0.5:22", false], ["10.0.0.5:80", true], ["http://10.0.0.5/", true], ["10.0.0.6", true]])
      test(`${o}: ${d}`, () => assert.equal(dentro(o, RED, fuera("ip", "10.0.0.5:22")), d));
  });
  test("una exclusión de red gana a un ítem libre dentro de alcance", () => {
    assert.equal(dentro("10.0.0.5", en("application", "10.0.0.5"), fuera("cidr", "10.0.0.0/24")), false);
  });
  describe("una exclusión mal escrita hace que nada quede dentro", () => {
    for (const x of ["10.0.0.5,6,7", "10.0.0.5 a 10.0.0.20", "10.0.0.5 al 10.0.0.20", "10.0.0.5 - 10.0.0.20", "10.0.0.0/255.255.255.0", "10.0.0.0 255.255.255.0", "10.0.0.0 0.0.0.255", "10.0.0.5:80,443", "10.0.0.5 (DC)", "10.0.0.*",
      "/admin", "/logout?x=1", "10.0.0.x", "10.x.x.x", "10.0.xx.xx", "10.0.0-1.1-20", "10.x.1.1-10", "10.x.x.1-20", "10.0–3.1.5", "10.0.0.abc", "10.0.0.5–20", "10.0.0.5-20:80"])
      for (const tipo of ["ip", "cidr", "domain", "url"])
        test(`${tipo} ${x}`, () => assert.equal(dentro("10.0.0.10", RED, fuera(tipo, x)), false));
  });
  test("una ruta que sube con parámetro de segmento no se toma por válida", () => {
    assert.equal(dentro("https://portal.acme.com/app/..;/admin", en("url", "https://portal.acme.com/app")), false);
  });
  test("una dirección mal escrita tampoco vale como dominio dentro de alcance", () => {
    for (const x of ["10.0.0.x", "10.0.0-1.1-20", "/admin"]) assert.equal(dentro(x, en("domain", x)), false, x);
    for (const x of ["10.0.0.5.nip.io", "163.com", "4.3.2.1.in-addr.arpa", "1.lab.acme.com", "1.2.acme.com", "168.192.in-addr.arpa"]) assert.equal(dentro(x, en("domain", x)), true, x);
  });
  // Hallazgos de la revisión de las correcciones.
  describe("🔴 un nombre numérico con un dominio de primer nivel real no es una dirección mal escrita", () => {
    for (const x of ["123.xyz", "1.2.xyz", "12.nz", "360.xxx", "123.xn--80adxhks", "12.xn--90ais"])
      test(x, () => {
        assert.equal(dentro(x, en("domain", x)), true);
        assert.equal(dentro("10.0.0.10", RED, fuera("domain", x)), true, "excluirlo no cierra todo el engagement");
      });
    for (const x of ["10.0.x", "10.0.xx", "10.x.xxx", "10.0.1-20", "10.0.0–20", "10.0.0.xyz",
      "192.168.xxx", "10.0.xxx", "10.xxx", "10.0.xyz", "172.16.nz", "172.16-31.xxx", "203.0.xxx", "203.0-5.xyz", "10.0.xxx:80", "10.0.xxx/24", "*.10.0.xxx", "http://10.0.xxx/"])
      for (const tipo of ["domain", "url"])
        test(`${tipo} ${x} sigue siendo ilegible`, () => assert.equal(dentro("10.0.0.10", RED, fuera(tipo, x)), false));
  });
  test("un nombre sin puntos solo vale si va solo", () => {
    assert.equal(dentro("DC01", en("domain", "DC01")), true);
    assert.equal(dentro("DC01", en("domain", "DC01"), fuera("domain", "DC02")), true);
  });
  describe("una ruta excluida no se esquiva", () => {
    for (const r of ["/admin", "//admin/x", "/admin/", "/%61dmin", "/%2561dmin", "/ADMIN/x", "/admin;x=1/y", "/x/..;/admin", "/x/..;a=1/admin", "/x/..%3b/admin", "/.;/admin", "/x/../admin", "/./admin", "/admin?x", "/admin#x"])
      test(r, () => assert.equal(dentro(`https://app.acme.com${r}`, SITIO, fuera("url", "https://app.acme.com/admin")), false));
    test("con comodín al final", () => {
      assert.equal(dentro("https://app.acme.com/admin/x", SITIO, fuera("url", "https://app.acme.com/admin/*")), false);
      assert.equal(dentro("https://app.acme.com/otro", SITIO, fuera("url", "https://app.acme.com/admin/*")), true);
    });
    test("un comodín en el medio no se interpreta", () => assert.equal(dentro("https://app.acme.com/otro", SITIO, fuera("url", "https://app.acme.com/*/admin")), false));
  });
  test("excluir un sitio por su URL vale para http y https, no para otros puertos", () => {
    const x = fuera("url", "https://app.acme.com");
    for (const o of ["http://app.acme.com/", "https://app.acme.com/x", "app.acme.com", "app.acme.com:443"]) assert.equal(dentro(o, SITIO, x), false, o);
    assert.equal(dentro("app.acme.com:8443", SITIO, x), true);
  });
  test("una URL con coma o punto y coma es una sola", () => {
    for (const o of ["https://app.acme.com/login;jsessionid=AB12", "https://app.acme.com/a?ids=1,2"]) assert.equal(dentro(o, SITIO), true, o);
    assert.equal(dentro("https://app.acme.com/a,https://otro.com/b", SITIO), false);
    assert.equal(dentro("https://app.acme.com/a, 8.8.8.8", SITIO), false);
  });
  test("una barra invertida no cambia de host", () => {
    for (const o of ["https://app.acme.com\\@malo.com/", "app.acme.com\\x"]) assert.equal(dentro(o, SITIO), false, o);
  });
  test("una exclusión por URL excluye su ruta y no el resto del sitio", () => {
    const a = [en("domain", "x.com"), fuera("url", "https://x.com/pagos")];
    assert.equal(evaluar("https://x.com/pagos/1", a).dentro, false);
    assert.equal(evaluar("https://x.com/blog", a).dentro, true);
  });
});

describe("ocultamiento", () => {
  const o = O.crear({ secreto: "s".repeat(32), engagementId: "e1", nombres: ["Banco Río", "Ana Pérez"] });
  const ocultos = [
    ["password=Sup3rSecreta!", "Sup3rSecreta!"],
    ["contraseña: hola123", "hola123"],
    ['"api_key": "abcd1234efgh"', "abcd1234efgh"],
    ["Authorization: Bearer abc.def-ghi", "abc.def-ghi"],
    ["Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"],
    ["https://usuario:clave99@host.com/x", "clave99"],
    ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk", "eyJhbGciOiJIUzI1NiJ9"],
    ["AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"],
    ["ghp_0123456789abcdefghijABCDEFGHIJ012345", "ghp_0123"],
    ["gnga_" + "a".repeat(64), "a".repeat(64)],
    ["-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", "MIIabc"],
    ["-----BEGIN OPENSSH PRIVATE KEY-----\nsin cierre", "sin cierre"],
    ["Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::", "31d6cfe0d16ae931b73c59d7e0c089c0"],
    ["root:$6$salt$hashlargohashlargo:18000", "$6$salt"],
    ["nxc smb 10.0.0.1 -u admin -p 'Verano2026'", "Verano2026"],
    ["mysql --password Secreta9", "Secreta9"],
    ["impacket-psexec CORP/juan:Clave123@10.0.0.1", "Clave123"],
    ["escribir a ana@bancorio.com", "ana@bancorio.com"],
    ["Informe para Banco Río", "Banco Río"],
    ["contacto ANA PÉREZ", "ANA PÉREZ"],
    // Hallazgos de la verificación independiente.
    ["DB_PASSWORD=Secreta123", "Secreta123"], ["MYSQL_ROOT_PASSWORD: Secreta123", "Secreta123"], ["JWT_SECRET=abcdef0123", "abcdef0123"],
    ["aws_secret_access_key = wJalrXUtnFEMI/K7", "wJalrXUtnFEMI"], ['"user_password":"Secreta123"', "Secreta123"], ['"userPassword": "Secreta123"', "Secreta123"],
    ["access_token=abc123def", "abc123def"], ["refresh_token=abc123def", "abc123def"], ["pass=Secreta123", "Secreta123"], ["DB_PASS=Secreta123", "Secreta123"],
    ["'password' => 'Secreta123'", "Secreta123"], ["define('DB_PASSWORD', 'Secreta123');", "Secreta123"], ["password: P@ss,word;99", "word;99"], ['password="dos palabras"', "palabras"],
    ["curl -u admin:Hola1234 http://x", "Hola1234"], ["mysql -uroot -pHola1234", "Hola1234"], ["smbclient -U ana%Hola1234 //h/c", "Hola1234"], ["xfreerdp /u:a /p:Hola1234 /v:h", "Hola1234"],
    ["nxc smb h -u a -H 31d6cfe0d16ae931b73c59d7e0c089c0", "31d6cfe0"], ["evil-winrm -i h -H 31d6cfe0d16ae931b73c59d7e0c089c0", "31d6cfe0"], ["psexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 a@h", "31d6cfe0"],
    ["ana::CORP:1122334455667788:0123456789abcdef0123456789abcdef:0101000000000000aabbccdd", "0123456789abcdef0123"],
    ["$krb5asrep$23$ana@CORP.LOCAL:0123456789abcdef0123456789abcdef$a1b2c3d4e5f60718", "a1b2c3d4e5f6"],
    ["$krb5tgs$23$*svc$CORP$http/web.corp.local~8080*$0123456789abcdef0123456789abcdef$a1b2c3d4e5f60718", "a1b2c3d4e5f6"],
    ["$krb5tgs$18$svc$CORP$*MSSQLSvc/db:1433*$0123456789abcdef01234567$a1b2c3d4e5f60718", "a1b2c3d4e5f6"],
    ["Cookie: PHPSESSID=abc123def456; x=1", "abc123def456"], ["Set-Cookie: sid=zzz999; Path=/", "zzz999"], ["JSESSIONID=AB12CD34", "AB12CD34"], ["nxc smb h -u a -p 12345678", "12345678"],
    ["Authorization: token abcd1234", "abcd1234"], ["Authorization: abcd1234abcd", "abcd1234abcd"], ["redis://:Hola1234@h", "Hola1234"],
    ["password is Hola1234", "Hola1234"], ["la contraseña es Hola1234", "Hola1234"], [`sk_live_${"a1B2c3".repeat(4)}`, "a1B2c3"],
    ["npm_abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghij"], ["https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX", "XXXXXXXX"],
    ["-----BEGIN PGP PRIVATE KEY BLOCK-----\nabcd", "abcd"], ["PuTTY-User-Key-File-2: ssh-rsa\nPrivate-Lines: 1\nAAAA", "AAAA"],
  ];
  for (const [texto, secreto] of ocultos)
    test(`oculta en ${JSON.stringify(texto.slice(0, 45))}`, () => {
      const r = o.texto(texto);
      assert.ok(!r.includes(secreto), r);
      assert.match(r, /\[OCULTO:/);
    });
  for (const limpio of ["nmap -sV -p 80,443 10.10.1.1", "curl https://app.ejemplo.com/login", "CVE-2024-12345 en Apache 2.4.49", "El formulario de contraseña no limita intentos",
    "gobuster dir -u http://app.ejemplo.com:8080/x -w lista.txt", "hydra -l admin -P lista.txt ssh://10.0.0.1", "bypass: se evita el control", "ffuf -u https://app.ejemplo.com/FUZZ", "nmap -p 22 10.0.0.1"])
    test(`no toca ${JSON.stringify(limpio)}`, () => assert.equal(o.texto(limpio), limpio));
  test("el cliente se oculta siempre en su campo, aunque el nombre sea corto", () => {
    const b = O.crear({ secreto: "s".repeat(32), engagementId: "e1", nombres: ["EY"] });
    const r = b.objeto({ cliente: "EY", title: "Pentest EY 2026", notes: "hey you" });
    assert.ok(!r.cliente.includes("EY") && !r.title.includes("EY"));
    assert.equal(r.notes, "hey you");
  });
  test("el mismo valor da siempre la misma marca, y otro engagement da otra", () => {
    const p = O.crear({ secreto: "s".repeat(32), engagementId: "e2", nombres: [] });
    assert.equal(o.texto("ana@x.com"), o.texto("ana@x.com"));
    assert.notEqual(o.texto("ana@x.com"), p.texto("ana@x.com"));
  });
  test("los objetivos conservan su nombre, pero no sus credenciales", () => {
    const b = O.crear({ secreto: "s".repeat(32), engagementId: "e1", nombres: ["acme"] });
    const r = b.objeto({ value: "acme", target: "https://u:p4ss@acme.com", affected_asset: "acme", notes: "acme" });
    assert.equal(r.value, "acme");
    assert.equal(r.affected_asset, "acme");
    assert.ok(!r.target.includes("p4ss") && r.target.includes("acme.com"));
    assert.ok(!r.notes.includes("acme"));
  });
  test("el nombre del cliente dentro de un dominio no rompe el dominio", () => {
    const b = O.crear({ secreto: "s".repeat(32), engagementId: "e1", nombres: ["acme"] });
    assert.equal(b.texto("curl https://www.acme.com/x"), "curl https://www.acme.com/x");
  });
  test("recorre listas y objetos anidados y respeta lo que no es texto", () => {
    const f = new Date(0);
    assert.deepEqual(o.objeto({ a: [{ b: 1, c: null, d: f }], e: true }), { a: [{ b: 1, c: null, d: f }], e: true });
    assert.ok(!JSON.stringify(o.objeto({ a: [{ b: "token=abcdef123" }] })).includes("abcdef123"));
  });
  test("apagado devuelve todo igual", () => {
    assert.equal(O.crear({ activo: false }).texto("password=x1234"), "password=x1234");
  });
  test("detecta marcas en lo que se quiere guardar", () => {
    assert.ok(O.tieneMarcas({ a: ["x [OCULTO:correo:abc123] y"] }));
    assert.ok(!O.tieneMarcas({ a: ["oculto"] }));
  });
  test("un texto hostil y largo no lo cuelga", () => {
    const t0 = Date.now();
    const hostiles = ["a".repeat(200000), "password=".repeat(20000), "-----BEGIN ".repeat(10000), "a@".repeat(50000),
      "nxc -p ".repeat(20000), "x://".repeat(40000), "eyJ".repeat(60000), "A/".repeat(80000), "a:".repeat(80000), " ".repeat(200000),
      "-eyJ".repeat(50000), ".eyJ".repeat(50000), "eyJaaaaaaaa.".repeat(16000), "sk-".repeat(66000), "Cookie:".repeat(28000), "a_password".repeat(20000), "password =".repeat(20000),
      "-u a:".repeat(40000), "mysql -p".repeat(25000), "-H ".repeat(66000), "a::b:".repeat(40000), "'password','".repeat(18000), "token".repeat(40000), "-hashes :".repeat(22000)];
    for (const s of hostiles) o.texto(s);
    assert.ok(Date.now() - t0 < 4000, `tardó ${Date.now() - t0} ms`);
  });
});

describe("límite por dirección", () => {
  test("🔴 una key cuyo dueño tiene que cambiar la contraseña deja de estar eximida", async () => {
    const k = acceso.nuevaKey();
    let debeCambiar = 0;
    const app = require("express")();
    const a = acceso.crear({
      qRow: async () => ({ id: "k", nombre: "k", nivel_max: "lectura", user_id: "u", username: "u", role: "admin", is_active: 1, must_change_password: debeCambiar }),
      qRun: async () => {}, secretoBase: "x", limitePorVentana: 5, // Techo por dirección: 20.
    });
    app.get("/", a.limitePorIp, a.autenticar, (req, res) => res.json({ ok: true }));
    const srv = await new Promise((ok) => { const s = app.listen(0, "127.0.0.1", () => ok(s)); });
    try {
      const pedir = async () => { const r = await fetch(`http://127.0.0.1:${srv.address().port}/`, { headers: { Authorization: `Bearer ${k}` } }); await r.text(); return r.status; };
      assert.equal(await pedir(), 200);
      debeCambiar = 1;
      assert.equal(await pedir(), 403);
      for (let i = 0; i < 25; i++) await pedir();
      assert.equal(await pedir(), 429);
    } finally { srv.closeAllConnections(); srv.close(); }
  });
  test("🔴 una key que ya entró no queda bloqueada por pedidos sin autenticar de la misma dirección", async () => {
    const buena = acceso.nuevaKey(), hash = acceso.hashDeKey(buena);
    const app = require("express")();
    const a = acceso.crear({
      qRow: async (q, [h]) => (h === hash ? { id: "k", nombre: "k", nivel_max: "lectura", user_id: "u", username: "u", role: "admin", is_active: 1 } : null),
      qRun: async () => {}, secretoBase: "x", limitePorVentana: 10, // Techo por dirección: 40.
    });
    app.get("/", a.limitePorIp, a.autenticar, (req, res) => res.json({ ok: true }));
    const srv = await new Promise((ok) => { const s = app.listen(0, "127.0.0.1", () => ok(s)); });
    try {
      const pedir = (k) => fetch(`http://127.0.0.1:${srv.address().port}/`, { headers: { Authorization: `Bearer ${k}` } });
      assert.equal((await pedir(buena)).status, 200);
      for (let i = 0; i < 45; i++) await (await pedir("gnga_" + "1".repeat(64))).text();
      const r = await pedir("gnga_" + "1".repeat(64));
      assert.equal(r.status, 429);
      assert.ok(r.headers.get("retry-after"), "dice cuándo reintentar");
      assert.equal((await pedir(buena)).status, 200);
      assert.equal((await pedir(acceso.nuevaKey())).status, 429);
    } finally { srv.closeAllConnections(); srv.close(); }
  });
});

describe("reintento ante un bloqueo mutuo", () => {
  const { reintentando } = require("../agentes/comun");
  const mutuo = () => Object.assign(new Error("x"), { code: "ER_LOCK_DEADLOCK" });
  test("🔴 repite la transacción entera y limpia lo que quedó afuera", async () => {
    let n = 0, limpiezas = 0;
    assert.equal(await reintentando(async () => { if (++n < 3) throw mutuo(); return "ok"; }, async () => { limpiezas++; }), "ok");
    assert.deepEqual([n, limpiezas], [3, 2]);
  });
  test("🔴 no repite otros errores ni insiste para siempre", async () => {
    let n = 0;
    await assert.rejects(reintentando(async () => { n++; throw new Error("otro"); }), /otro/);
    assert.equal(n, 1);
    await assert.rejects(reintentando(async () => { n++; throw mutuo(); }));
    assert.equal(n, 5);
  });
});

test("🔴 la huella de un hallazgo no depende de la zona horaria del servidor", () => {
  const { execFileSync } = require("node:child_process");
  const ver = (TZ) => execFileSync(process.execPath, ["-e", `const H=require(${JSON.stringify(require.resolve("../agentes/hallazgos"))});process.stdout.write(H.huellaDe({title:"x",remediation_due_date:new Date(2030,4,7),retested_at:new Date(2030,4,7,23,59,1)}))`], { env: { ...process.env, TZ } }).toString();
  assert.equal(ver("UTC"), ver("America/Argentina/Buenos_Aires"));
});

describe("el activo que ya tiene un hallazgo", () => {
  const { evaluador, juzgarActivo } = require("../agentes/alcance");
  const en = (type, value, in_scope = 1) => ({ type, value, in_scope });
  const ALC = [en("cidr", "10.10.0.0/16"), en("domain", "cliente.test"), en("domain", "*.cliente.test"), en("application", "API v2 en api.externa.test"), en("ip", "2001:db8::5"),
    en("ip", "10.10.9.9", 0), en("domain", "pagos.sub.cliente.test", 0), en("url", "https://web.cliente.test/app", 0), en("domain", "intranet", 0), en("application", "Portal Pagos", 0)];
  const pasa = (a, items = ALC) => juzgarActivo(a, evaluador(items)) === null;
  describe("🔴 no se toca lo excluido ni lo que está claramente fuera", () => {
    for (const a of ["10.10.9.9", "ssh://10.10.9.9", "10.10.9.9/admin", "10.10.9.9:22/tcp", "10.10.0.0/16", "web.cliente.test/app/admin", "pagos.sub.cliente.test/login", "intranet", "intranet/x", "Portal Pagos", "Portal 10.10.9.9",
      "10.0.0.5", "10.0.0.5/admin", "10.0.0.5:8443/login", "10.0.0.5-20", "8.8.0.0/24", "evil.test", "evil.test.", "evil.test/login", "evil.test:8443/login", "https://evil.test/x", "https://u:p@evil.test/", "ftp://evil.test", "ssh://evil.test",
      "smb://10.0.0.5/c$", "evil.sh", "evil.py", "evil.rs", "xn--bcher-kva.example", "bücher.example", "[2001:db8::9]:443", "2001:db8::9", "srv (8.8.8.8) 443/tcp", "srv-web[10.0.0.5]", "host=10.0.0.5", "{10.0.0.5}", "a|10.0.0.5", "evil.test:", "10.0.0.5:",
      "evil.test (prod)", "10.10.1.1, 8.8.8.8", "10.10.1.1 y evil.test", "\"evil.test\"", "<https://evil.test/a>", "evil.test/a src/db.js",
      "https://jenkins:8080/login", "http://intranet2/x", "http://localhost:8080/", "ssh://srv-db", "jenkins:8080/tcp", "10.0.0.5,https://app.cliente.test/", "evil.test;https://app.cliente.test/", "https://app.cliente.test/ http://intranet2/",
      "evil.test/login srv:443", "evil.test!", "//evil.test/x", "*.evil.test", "evil.test→10.10.0.1", "evil.test / cliente.test", "http://[2001:db8::9]", "(http://[2001:db8::9])", "https://[2001:db8::9], 10.10.1.1", "[http://evil.test]", "raro://jenkins", "github.com/admin", "ssh://github.com/org/app", "https://github.com:8443/a/b", "evil.test/a b.test:443", "evil.test/a b.test/x:443", "evil.test/a 10.0.0.5/x:443", "evil.test src/db.js:42", "10.0.0.5 src/db.js:42"])
      test(a, () => assert.equal(pasa(a), false));
  });
  describe("🔴 lo que está dentro sigue editable, aunque nombre otra cosa en la URL", () => {
    for (const a of ["10.10.1.1", "10.10.1.1:80/tcp", "ssh://10.10.1.1", "cliente.test", "app.cliente.test:443", "https://app.cliente.test/x", "app.cliente.test/x", "[2001:db8::5]:443", "10.10.1.0/24", "10.10.1.1 10.10.1.2", "API v2 en api.externa.test",
      "https://app.cliente.test/r?u='https://evil.test'", "https://app.cliente.test/ssrf?h=a,10.0.0.1", "https://app.cliente.test/?q=(evil.test)", "https://app.cliente.test/?cb=a;b.evil.test", "srv-web (10.10.1.1) 80/tcp", "app.cliente.test (10.10.1.1) 443/tcp"])
      test(a, () => assert.equal(pasa(a), true));
  });
  describe("🔴 una etiqueta de una persona o del seguimiento no se juzga, con o sin alcance", () => {
    for (const a of ["", null, "Tablero", "Aplicación web", "N/A", "Dockerfile", "src/db.js:42", "org/app", "github.com/org/app src/db.js:42", "github.com/org/app", "gitlab.otro.test/org/app src/db.js:42", "srv-web", "s3://balde", "server.js",
      "web.config", "index.aspx", "log4j-core-2.14.1.jar", "package.json", "v1.2.3", "registry/app:1.2", "alpine:3.18",
      "nginx:1.25", "Dockerfile:12", "https://github.com/org/app", "https://github.com/org/app src/db.js:42", "gitlab.otro.test/org/app main.py:7", "docker://imagen", "gs://balde/x"])
      test(String(a), () => { assert.equal(pasa(a), true); assert.equal(pasa(a, []), true); });
  });
  test("🔴 con una exclusión ilegible nada es editable", () => {
    for (const a of ["Tablero", "10.10.1.1"]) assert.equal(pasa(a, [...ALC, en("ip", "10.0.0.5,6", 0)]), false);
    assert.equal(pasa("", [...ALC, en("ip", "10.0.0.5,6", 0)]), true, "sin activo no hay qué juzgar");
  });
});
