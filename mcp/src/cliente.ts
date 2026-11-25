import { randomUUID } from 'node:crypto'
import type { Config } from './config.ts'

const BASE = '/api/agente/v1'
const INTENTOS = 3
const ESPERA_MAX_MS = 10_000
const REINTENTABLES = new Set([429, 502, 503, 504])

export class ErrorGungnir extends Error {
  readonly codigo: number | null
  readonly detalle: Record<string, unknown>
  constructor(mensaje: string, codigo: number | null = null, detalle: Record<string, unknown> = {}) {
    super(mensaje)
    this.codigo = codigo
    this.detalle = detalle
  }
}

export interface Archivo { nombre: string; contenido: Uint8Array }
export interface Opciones {
  consulta?: Record<string, string | number | boolean | undefined>
  cuerpo?: unknown
  archivo?: Archivo
}
export type Respuesta = Record<string, unknown>

export interface Cliente {
  pedir(metodo: 'GET' | 'POST' | 'PUT' | 'DELETE', ruta: string, opciones?: Opciones): Promise<Respuesta>
}

const dormir = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms))

/**
 * Cliente de la API de agentes. Toda escritura lleva una Idempotency-Key que se repite en los
 * reintentos: si la respuesta se perdió en el camino, el servidor no vuelve a escribir.
 */
export function crearCliente(cfg: Config, { pausaMs = 500, fetch: pedirHttp = fetch }: { pausaMs?: number; fetch?: typeof fetch } = {}): Cliente {
  return {
    async pedir(metodo, ruta, { consulta, cuerpo, archivo } = {}) {
      const url = new URL(cfg.url + BASE + ruta)
      for (const [k, v] of Object.entries(consulta ?? {})) if (v !== undefined) url.searchParams.set(k, String(v))
      const headers: Record<string, string> = { Authorization: `Bearer ${cfg.apiKey}`, Accept: 'application/json' }
      if (metodo !== 'GET') headers['Idempotency-Key'] = randomUUID()

      let ultimo: ErrorGungnir | null = null
      for (let intento = 1; intento <= INTENTOS; intento++) {
        let res: Response
        let texto: string
        try {
          res = await pedirHttp(url, {
            method: metodo,
            headers: cuerpo !== undefined && !archivo ? { ...headers, 'Content-Type': 'application/json' } : headers,
            // Una redirección mandaría la key a otro destino.
            redirect: 'error',
            signal: AbortSignal.timeout(cfg.tiempoMs),
            body: archivo ? formulario(archivo, cuerpo) : cuerpo === undefined ? undefined : JSON.stringify(cuerpo),
          })
          texto = await res.text()
        } catch (e) {
          const lento = e instanceof Error && e.name === 'TimeoutError'
          ultimo = new ErrorGungnir(lento
            ? `Gungnir no respondió en ${cfg.tiempoMs / 1000} segundos.`
            : `No se pudo conectar con Gungnir en ${cfg.url}. Verificá que esté en marcha.`)
          if (intento < INTENTOS) await dormir(pausaMs * intento)
          continue
        }

        const json = leerJson(texto)
        if (res.ok) {
          if (!json) throw new ErrorGungnir(`Lo que respondió ${cfg.url} no es la API de Gungnir: revisá GUNGNIR_URL.`, res.status)
          return json
        }
        const { error, ...detalle } = json ?? {}
        ultimo = new ErrorGungnir(typeof error === 'string' ? error : mensajePorCodigo(res.status), res.status, detalle)
        const enCurso = res.status === 409 && detalle['en_curso'] === true
        if (!enCurso && !REINTENTABLES.has(res.status)) throw ultimo
        const pedida = Number(res.headers.get('retry-after')) * 1000
        if (pedida > ESPERA_MAX_MS) throw ultimo
        if (intento < INTENTOS) await dormir(pedida > 0 ? pedida : pausaMs * intento)
      }
      throw ultimo ?? new ErrorGungnir('No se pudo completar el pedido.')
    },
  }
}

function formulario({ nombre, contenido }: Archivo, campos: unknown): FormData {
  const f = new FormData()
  for (const [k, v] of Object.entries((campos ?? {}) as Record<string, unknown>)) if (v !== undefined && v !== null) f.append(k, String(v))
  f.append('archivo', new Blob([contenido as Uint8Array<ArrayBuffer>]), nombre)
  return f
}

function leerJson(texto: string): Respuesta | null {
  try {
    const j: unknown = JSON.parse(texto)
    return j && typeof j === 'object' && !Array.isArray(j) ? (j as Respuesta) : null
  } catch { return null }
}

function mensajePorCodigo(codigo: number): string {
  if (codigo === 401) return 'Gungnir rechazó la key.'
  if (codigo === 404) return 'Gungnir no conoce esa ruta: puede ser una versión sin soporte de agentes.'
  if (codigo === 429) return 'Se superó el límite de pedidos.'
  return `Gungnir respondió ${codigo}.`
}
