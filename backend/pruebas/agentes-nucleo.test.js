// Núcleo de los agentes: niveles de autonomía, alcance y ocultamiento de datos. Sin base ni red.
"use strict";
const { test, describe } = require("node:test");
const assert = require("node:assert/strict");
const N = require("../agentes/niveles");
const { evaluar } = require("../agentes/alcance");
const O = require("../agentes/ocultar");

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
    ["168427777", true], ["0x0a0a0101", true], ["010.10.1.1", false],
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
  ];
  for (const [texto, secreto] of ocultos)
    test(`oculta en ${JSON.stringify(texto.slice(0, 45))}`, () => {
      const r = o.texto(texto);
      assert.ok(!r.includes(secreto), r);
      assert.match(r, /\[OCULTO:/);
    });
  for (const limpio of ["nmap -sV -p 80,443 10.10.1.1", "curl https://app.ejemplo.com/login", "CVE-2024-12345 en Apache 2.4.49", "El formulario de contraseña no limita intentos"])
    test(`no toca ${JSON.stringify(limpio)}`, () => assert.equal(o.texto(limpio), limpio));
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
      "nxc -p ".repeat(20000), "x://".repeat(40000), "eyJ".repeat(60000), "A/".repeat(80000), "a:".repeat(80000), " ".repeat(200000)];
    for (const s of hostiles) o.texto(s);
    assert.ok(Date.now() - t0 < 4000, `tardó ${Date.now() - t0} ms`);
  });
});
