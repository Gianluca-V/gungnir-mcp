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

// El grupo entero es lo que se oculta. Todas las repeticiones tienen tope, para que ningún texto
// las vuelva cuadráticas. Los tipos no pueden ser palabras que otra regla busque (clave, token).
const SECRETOS = [
  ["credencial", /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----(?:(?!-----)[\s\S]){0,20000}(?:-----END [A-Z ]{0,40}PRIVATE KEY-----)?/g],
  ["acceso", /\beyJ[\w-]{8,4000}\.[\w-]{4,8000}(?:\.[\w-]{0,4000})?/g],
  ["acceso", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ["acceso", /\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_\w{20,255}|xox[abprs]-[\w-]{10,255}|AIza[\w-]{30,60}|sk-[\w-]{20,255}|glpat-[\w-]{20,255}|gng[ar]_[0-9a-f]{16,128})/g],
  ["acceso", /(?<=\b(?:Bearer|Basic|Negotiate|NTLM) )[A-Za-z0-9+/=._~-]{6,8000}/gi],
  ["credencial", /(?<=:\/\/[^\s:/@]{1,100}:)[^\s@/]{1,200}(?=@)/g],
  ["credencial", /(?<=\b[\w.-]{1,40}\/[\w.-]{1,60}:)[^\s@:]{1,120}(?=@[\w.[])/g],
  ["hash", /\b[0-9a-f]{32}:[0-9a-f]{32}\b/gi],
  ["hash", /\$(?:1|2[abxy]|5|6|y|argon2id?|krb5\w{2,8})\$[\w./$*@=,+-]{6,4000}/g],
  ["credencial", /(?<=\b(?:password|passwd|passphrase|pwd|contraseña|contrasena|clave|secret|secreto|token|api[_-]?key|apikey|client_secret|access_key)["']?[ \t]{0,3}[:=][ \t]{0,3}["']?)(?!\[OCULTO:)[^\s"'&;,<>]{4,400}/giu],
  ["credencial", /(?<=--(?:password|pass|passwd|token|secret|api-key)[ =]["']?)(?!\[OCULTO:)[^\s"']{2,400}/gi],
];
const CORREO = ["correo", /(?<![\w.+-])[\w.+-]{1,64}@[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){1,6}\b/gi];
// -p significa puerto en casi todo: solo se trata como clave detrás de estas herramientas.
const CON_P = /\b(?:crackmapexec|cme|netexec|nxc|smbmap|evil-winrm|sshpass|hydra|bloodhound-python|certipy|kerbrute|ldapdomaindump)\b/i;
const VALOR_P = /(?<=\s-(?:p|P)[ =]?)(?:'[^'\n]{1,200}'|"[^"\n]{1,200}"|(?![\d,-]{1,40}(?:\s|$))[^\s'"]{1,200})/g;

const escapar = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function crear({ activo = true, secreto = "", engagementId = "", nombres = [] } = {}) {
  if (!activo) return { activo: false, texto: (s) => s, objeto: (v) => v };

  const llave = crypto.createHmac("sha256", secreto).update(`ocultar:${engagementId}`).digest();
  const marca = (tipo, valor) =>
    `[OCULTO:${tipo}:${crypto.createHmac("sha256", llave).update(valor.toLocaleLowerCase("es")).digest("hex").slice(0, 6)}]`;
  const aplicar = (s, [tipo, re]) => s.replace(re, (m) => marca(tipo, m));

  // Pegado a un punto, una arroba o un guion es parte de un dominio y hace falta entero.
  const patronesNombre = [...new Set(nombres.map((n) => String(n || "").trim()).filter((n) => n.length >= 3))]
    .sort((a, b) => b.length - a.length)
    .map((n) => ["cliente", new RegExp(`(?<![\\p{L}\\p{N}_.@/-])${escapar(n)}(?![\\p{L}\\p{N}_@-]|\\.[\\p{L}\\p{N}])`, "giu")]);

  function secretos(s) {
    for (const p of SECRETOS) s = aplicar(s, p);
    if (CON_P.test(s))
      s = s.split("\n").map((l) => (CON_P.test(l) ? l.replace(VALOR_P, (m) => marca("credencial", m.replace(/^['"]|['"]$/g, ""))) : l)).join("\n");
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
