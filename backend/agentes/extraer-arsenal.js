"use strict";
/**
 * Genera data/arsenal.json con los comandos que el panel trae escritos en
 * frontend/src/features/comandos/index.tsx, para poder servirlos por la API.
 *
 * El panel sigue siendo la fuente: así las novedades del upstream entran sin conflictos. Después de
 * traerlas se corre `npm run arsenal`; una prueba avisa si el archivo quedó viejo.
 */
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const FUENTE = path.join(__dirname, "..", "..", "frontend", "src", "features", "comandos", "index.tsx");
const DESTINO = path.join(__dirname, "..", "data", "arsenal.json");

function extraer(fuente = fs.readFileSync(FUENTE, "utf8")) {
  const s = fuente.replace(/\r\n/g, "\n");
  const marca = "export const COMANDOS: Comando[] = [";
  const ini = s.indexOf(marca);
  const fin = s.indexOf("\n]", ini);
  if (ini < 0 || fin < 0) throw new Error("no se encontró la lista COMANDOS en el panel");
  const lista = vm.runInNewContext(`(${s.slice(ini + marca.length - 1, fin + 2)})`, {}, { timeout: 2000 });
  return Array.from(lista, ({ id, tool, phase, category, title, command, description, tags, notes, mitreId }) =>
    JSON.parse(JSON.stringify({ id, tool, phase, category, title, command, description, tags, notes, mitreId })));
}

if (require.main === module) {
  const lista = extraer();
  fs.writeFileSync(DESTINO, JSON.stringify(lista, null, 1) + "\n");
  console.log(`${lista.length} comandos en ${path.relative(process.cwd(), DESTINO)}`);
}

module.exports = { extraer, FUENTE, DESTINO };
