import { open, realpath } from 'node:fs/promises'
import path from 'node:path'
import type { Archivo } from './cliente.ts'
import { ErrorGungnir } from './cliente.ts'

const TOPE = 20 * 1024 * 1024

/**
 * Lee un archivo para subirlo. Tiene que estar dentro de `carpeta` una vez resueltos los enlaces
 * simbólicos, y ninguna parte de su ruta puede ser oculta (.env, .git, .ssh).
 */
export async function leerArchivo(carpeta: string, ruta: string): Promise<Archivo> {
  if (ruta.includes('\0')) throw new ErrorGungnir('La ruta no es válida.')
  const raiz = await realpath(carpeta).catch(() => { throw new ErrorGungnir('La carpeta de trabajo (GUNGNIR_CARPETA) no existe.') })
  const real = await realpath(path.resolve(raiz, ruta)).catch(() => { throw new ErrorGungnir(`No existe el archivo "${ruta}" dentro de la carpeta de trabajo.`) })
  const relativa = path.relative(raiz, real)
  if (!relativa || relativa.startsWith('..') || path.isAbsolute(relativa)) throw new ErrorGungnir('El archivo está fuera de la carpeta de trabajo (GUNGNIR_CARPETA).')
  if (relativa.split(path.sep).some((p) => p.startsWith('.'))) throw new ErrorGungnir('Los archivos y carpetas ocultos no se pueden subir.')

  const f = await open(real, 'r')
  try {
    const datos = await f.stat()
    if (!datos.isFile()) throw new ErrorGungnir('La ruta no es un archivo.')
    if (datos.size > TOPE) throw new ErrorGungnir('El archivo supera los 20 MB.')
    if (datos.size === 0) throw new ErrorGungnir('El archivo está vacío.')
    return { nombre: path.basename(real), contenido: await f.readFile() }
  } finally { await f.close() }
}
