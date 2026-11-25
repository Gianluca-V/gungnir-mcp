import path from 'node:path'

export interface Config {
  url: string
  apiKey: string
  /** Única carpeta desde la que se pueden subir archivos. */
  carpeta: string
  engagement: string | null
  tiempoMs: number
}

const FORMATO_KEY = /^gnga_[0-9a-f]{64}$/
const LOCALES = new Set(['localhost', '127.0.0.1', '[::1]'])
// Adentro del contenedor es el equipo donde corre y no sale a la red. Afuera lo resuelve cualquier DNS.
const ANFITRION = 'host.docker.internal'
const FORMATO_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i

/** Lee la configuración del entorno. Los errores nunca incluyen el valor de la key. */
export function leerConfig(env: NodeJS.ProcessEnv, carpetaActual: string): Config {
  const cruda = env['GUNGNIR_URL']?.trim()
  if (!cruda) throw new Error('Falta GUNGNIR_URL (por ejemplo, http://localhost:3006).')
  let url: URL
  try { url = new URL(cruda) } catch { throw new Error('GUNGNIR_URL no es una URL válida.') }
  if (url.username || url.password) throw new Error('GUNGNIR_URL no puede llevar usuario ni contraseña.')
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error('GUNGNIR_URL tiene que ser http o https.')
  const local = LOCALES.has(url.hostname) || (url.hostname === ANFITRION && env['GUNGNIR_EN_CONTENEDOR'] === '1')
  if (url.protocol === 'http:' && !local && env['GUNGNIR_PERMITIR_HTTP'] !== '1')
    throw new Error('GUNGNIR_URL usa http hacia otro equipo y la key viajaría sin cifrar. Usá https, o GUNGNIR_PERMITIR_HTTP=1 si la red es de confianza.')

  const apiKey = env['GUNGNIR_API_KEY']?.trim() ?? ''
  if (!FORMATO_KEY.test(apiKey)) throw new Error('Falta GUNGNIR_API_KEY o no tiene el formato gnga_... Se crea en el panel, en Integraciones > Agentes.')

  const segundos = Number(env['GUNGNIR_TIEMPO_SEGUNDOS']?.trim() || 30)
  if (!Number.isFinite(segundos) || segundos < 1 || segundos > 300) throw new Error('GUNGNIR_TIEMPO_SEGUNDOS tiene que estar entre 1 y 300.')

  const engagement = env['GUNGNIR_ENGAGEMENT']?.trim() || null
  if (engagement && !FORMATO_ID.test(engagement)) throw new Error('GUNGNIR_ENGAGEMENT tiene que ser el id de un engagement (ver listar_engagements).')

  return {
    url: url.origin + url.pathname.replace(/\/+$/, ''),
    apiKey,
    carpeta: path.resolve(env['GUNGNIR_CARPETA']?.trim() || carpetaActual),
    engagement,
    tiempoMs: segundos * 1000,
  }
}
