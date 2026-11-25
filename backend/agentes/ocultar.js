"use strict";
/**
 * Oculta datos del cliente y secretos en lo que se entrega a un agente.
 *
 * Reemplaza cada valor por una marca estable `[OCULTO:tipo:xxxxxx]`: el mismo valor da la misma
 * marca dentro de un engagement, así el agente puede relacionar apariciones sin ver el dato. La
 * marca sale de un HMAC, no se puede revertir.
 *
 * La detección es por patrones: reduce lo que sale al proveedor del modelo, no lo garantiza. Los
 * objetivos (alcance, activo afectado) conservan su nombre porque el agente los necesita; solo se
 * les quitan las credenciales.
 */
const crypto = require("crypto");

const MARCA = /\[OCULTO:[a-z]+:[0-9a-f]{6}\]/;
const CLAVES_OBJETIVO = new Set(["value", "target", "affected_asset", "objetivo", "objetivos", "original_name"]);
const TOPE = 200000;

// Una palabra que anuncia una clave, sola o dentro de un nombre (DB_PASSWORD, userPassword), y después
// su valor: entre comillas hasta que cierran, o hasta el próximo espacio.
const PALABRA = "(?:password|passwd|passphrase|(?<![a-z])pass|pwd|contraseña|contrasena|(?<![a-z])clave|secret|secreto|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|credencial)";
const SEPARADOR = "(?:[\"']?[ \\t]{0,3}(?:=>|[:=])[ \\t]{0,3}|[\"'][ \\t]{0,3},[ \\t]{0,3}(?=[\"']))";
const CON_VALOR = new RegExp(
  `(?<=${PALABRA}(?:[_-]?(?:hash|key|id|value|\\d{1,3}))?${SEPARADOR})(?!["']?\\[OCULTO:)(?:"[^"\\r\\n]{1,400}"|'[^'\\r\\n]{1,400}'|[^\\s"'<>(){}]{3,400})`, "giu");

// El grupo entero es lo que se oculta. Todas las repeticiones tienen tope, para que ningún texto
// las vuelva cuadráticas. Los tipos no pueden ser palabras que otra regla busque (clave, token, credencial).
const SECRETOS = [
  ["cred", /-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----(?:(?!-----)[\s\S]){0,20000}(?:-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----)?/g],
  ["cred", /PuTTY-User-Key-File-\d[\s\S]{0,20000}/g],
  ["acceso", /(?<![\w-])eyJ[\w-]{8,4000}\.[\w-]{4,8000}(?:\.[\w-]{0,4000})?/g],
  ["acceso", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ["acceso", /\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_\w{20,255}|xox[abprs]-[\w-]{10,255}|AIza[\w-]{30,60}|sk-[\w-]{20,255}|glpat-[\w-]{20,255}|[sr]k_(?:live|test)_\w{10,255}|npm_\w{30,255}|SG\.[\w-]{16,64}\.[\w-]{16,128}|hooks\.slack\.com\/services\/[\w/]{10,255}|gng[ar]_[0-9a-f]{16,128})/g],
  ["acceso", /(?<=\b(?:Bearer|Basic|Negotiate|NTLM) )[A-Za-z0-9+/=._~-]{6,8000}/gi],
  ["acceso", /(?<=\bAuthorization:[ \t]{0,3}(?:(?!Bearer|Basic|Negotiate|NTLM)\w{1,20} )?)(?!(?:Bearer|Basic|Negotiate|NTLM|\w{1,20}) )(?!\[OCULTO:)[^\s"']{4,8000}/gi],
  ["cred", /(?<=\b(?:password|passwd|pwd|contraseña|contrasena)[ \t](?:is|es)[ \t])[^\s"',;]{4,200}/giu],
  ["acceso", /(?<=\b(?:Set-)?Cookie:[ \t]{0,3})[^\r\n[ \t][^\r\n]{0,4000}/gi],
  ["acceso", /(?<=\b(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid|sessionid|laravel_session|ci_session)=)[^\s;"']{4,1000}/gi],
  ["hash", /[\w.$-]{1,64}::[\w.-]{0,64}:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]{20,4000}/gi],
  ["hash", /(?<=\s(?:-H|--?hashes|\/pth:?)[ =]{0,2}["']?:?)[0-9a-f]{32}(?::[0-9a-f]{32})?/gi],
  ["cred", /(?<=:\/\/[^\s:/@]{0,100}:)[^\s@/]{1,200}(?=@)/g],
  ["cred", /(?<=\b[\w.-]{1,40}\/[\w.-]{1,60}:)[^\s@:]{1,120}(?=@[\w.[])/g],
  ["hash", /\b[0-9a-f]{32}:[0-9a-f]{32}\b/gi],
  ["hash", /\$(?:1|2[abxy]|5|6|y|argon2id?|krb5\w{2,8})\$[\w./$*@=,+-]{6,4000}/g],
  ["cred", CON_VALOR],
  // usuario:clave detrás de -u, sin confundir una URL; usuario%clave de smbclient; /p: de xfreerdp.
  ["cred", /(?<=\s(?:-u|--user)[ =]{0,2}["']?[^\s:"'%/]{1,60}:)(?!\/\/)(?!\[OCULTO:)[^\s"']{1,200}/g],
  ["cred", /(?<=\s-U[ =]{0,2}["']?[^\s%"']{1,60}%)(?!\[OCULTO:)[^\s"']{1,200}/g],
  ["cred", /(?<=\s\/p(?:ass|assword)?:)(?!\[OCULTO:)[^\s"']{1,200}/gi],
  ["cred", /(?<=\b(?:mysql|mysqldump|mariadb)\b[^\n]{0,120}\s-p)(?!\[OCULTO:)[^\s"'=-][^\s"']{0,200}/g],
  ["cred", /(?<=--(?:password|pass|passwd|token|secret|api-key)[ =]["']?)(?!\[OCULTO:)[^\s"']{2,400}/gi],
];
const CORREO = ["correo", /(?<![\w.+-])[\w.+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,6}\b/gi];
// -p significa puerto en casi todo, y -P es un archivo o un puerto en estas: solo se trata como clave detrás de estas herramientas.
const CON_P = /\b(?:crackmapexec|cme|netexec|nxc|smbmap|evil-winrm|sshpass|hydra|bloodhound-python|certipy|kerbrute|ldapdomaindump)\b/i;
const VALOR_P = /(?<=\s-p[ =]?)(?:'[^'\n]{1,200}'|"[^"\n]{1,200}"|[^\s'"]{1,200})/g;

const escapar = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function crear({ activo = true, secreto = "", engagementId = "", nombres = [] } = {}) {
  if (!activo) return { activo: false, texto: (s) => s, objeto: (v) => v };

  const llave = crypto.createHmac("sha256", secreto).update(`ocultar:${engagementId}`).digest();
  const marca = (tipo, valor) =>
    `[OCULTO:${tipo}:${crypto.createHmac("sha256", llave).update(valor.toLocaleLowerCase("es")).digest("hex").slice(0, 6)}]`;
  const sinComillas = (m) => m.replace(/^(["'])([^]*)\1$/, "$2");
  const aplicar = (s, [tipo, re]) => s.replace(re, (m) => marca(tipo, sinComillas(m)));

  // Pegado a un punto, una arroba o un guion es parte de un dominio y hace falta entero.
  const patronesNombre = [...new Set(nombres.map((n) => String(n || "").trim()).filter((n) => n.length >= 2))]
    .sort((a, b) => b.length - a.length)
    .map((n) => ["cliente", new RegExp(`(?<![\\p{L}\\p{N}_.@/-])${escapar(n)}(?![\\p{L}\\p{N}_@-]|\\.[\\p{L}\\p{N}])`, n.length > 2 ? "giu" : "gu")]);

  function secretos(s) {
    for (const p of SECRETOS) s = aplicar(s, p);
    if (CON_P.test(s))
      s = s.split("\n").map((l) => (CON_P.test(l) ? l.replace(VALOR_P, (m) => marca("cred", m.replace(/^['"]|['"]$/g, ""))) : l)).join("\n");
    return s;
  }
  function texto(v, esObjetivo = false) {
    if (typeof v !== "string" || !v) return v;
    let s = secretos(v.length > TOPE ? v.slice(0, TOPE) : v);
    if (esObjetivo) return s;
    s = aplicar(s, CORREO);
    for (const p of patronesNombre) s = aplicar(s, p);
    return s;
  }
  function objeto(v, clave = "") {
    if (clave === "cliente" && typeof v === "string" && v) return marca("cliente", v);
    if (typeof v === "string") return texto(v, CLAVES_OBJETIVO.has(clave));
    if (Array.isArray(v)) return v.map((x) => objeto(x, clave));
    if (v && typeof v === "object" && [Object.prototype, null].includes(Object.getPrototypeOf(v)))
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, objeto(x, k)]));
    return v;
  }
  return { activo: true, texto, objeto };
}

/** ¿Hay marcas en lo que se quiere guardar? Guardarlas pisaría el dato real con la marca. */
function tieneMarcas(v) {
  if (typeof v === "string") return MARCA.test(v);
  if (v && typeof v === "object") return Object.values(v).some(tieneMarcas);
  return false;
}

module.exports = { crear, tieneMarcas };
