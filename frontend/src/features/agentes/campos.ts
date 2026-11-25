/** Campos de un hallazgo que propone un agente, con las mismas reglas que valida el backend. */
export interface Campo {
  nombre: string
  tipo: 'texto' | 'largo' | 'numero' | 'lista'
  max?: number
  opciones?: readonly string[]
  obligatorio?: boolean
}

const texto = (nombre: string, max: number, obligatorio = false): Campo => ({
  nombre,
  tipo: 'texto',
  max,
  obligatorio,
})
const largo = (nombre: string, max = 100_000, obligatorio = false): Campo => ({
  nombre,
  tipo: 'largo',
  max,
  obligatorio,
})
const opcion = (nombre: string, ...opciones: string[]): Campo => ({
  nombre,
  tipo: 'texto',
  opciones,
})

export const CAMPOS: Campo[] = [
  texto('title', 500, true),
  texto('affected_asset', 500, true),
  opcion('severity', 'critical', 'high', 'medium', 'low', 'info'),
  opcion('status', 'open', 'in_remediation', 'fixed'),
  largo('description'),
  largo('steps_to_reproduce'),
  largo('recommendation'),
  largo('executive_summary', 20_000),
  { nombre: 'cvss_score_31', tipo: 'numero', max: 5 },
  texto('cvss_vector_31', 100),
  { nombre: 'cvss_score_40', tipo: 'numero', max: 5 },
  texto('cvss_vector_40', 200),
  texto('cwe_id', 20),
  texto('cwe_name', 200),
  texto('owasp_category', 100),
  texto('owasp_year', 10),
  texto('mitre_tactic', 100),
  texto('mitre_technique_id', 20),
  texto('mitre_technique_name', 200),
  opcion('business_risk', 'high', 'medium', 'low'),
  opcion('exploitability', 'proven', 'functional', 'poc', 'theoretical'),
  opcion(
    'phase_type',
    'planning',
    'recon',
    'scanning',
    'exploitation',
    'post_exploitation',
    'reporting'
  ),
  { nombre: 'references_list', tipo: 'lista', max: 50_000 },
]

/** Lo que se propone al reprobar un hallazgo. */
export const CAMPOS_RETEST: Campo[] = [
  opcion('resultado', 'passed', 'failed', 'partial'),
  texto('objetivo', 500, true),
  opcion('retest_severity', 'critical', 'high', 'medium', 'low', 'info'),
  largo('notas', 20_000, true),
]

/** Las opciones que se pueden dejar sin valor. */
export const VACIABLES = new Set(['phase_type', 'retest_severity'])

/** Los que se muestran siempre en un hallazgo nuevo, aunque el agente no los haya mandado. */
export const CAMPOS_ALTA = new Set([
  'title',
  'affected_asset',
  'severity',
  'description',
  'steps_to_reproduce',
  'recommendation',
  'cvss_score_31',
  'cvss_vector_31',
  'cwe_id',
])

export function comoTexto(v: unknown): string {
  if (v === null || v === undefined) return ''
  return Array.isArray(v) ? v.join('\n') : String(v)
}

const lineas = (s: string) =>
  s
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean)
const numero = (s: string) => Number(s.trim().replace(',', '.'))

/** La clave del error a mostrar, o null. */
export function errorDe(c: Campo, valor: string): string | null {
  const v = valor.trim()
  if (!v) return c.obligatorio ? 'required' : null
  if (c.tipo === 'numero')
    return numero(v) >= 0 && numero(v) <= 10 ? null : 'score'
  if (c.tipo === 'lista') {
    const l = lineas(v)
    return l.length <= 50 && l.every((x) => x.length <= 1000) ? null : 'list'
  }
  return null
}

/** Lo que se manda a aprobar. Lo que no se tocó va igual a como lo propuso el agente. */
export function armarDatos(
  campos: Campo[],
  valores: Record<string, string>,
  propuesto: Record<string, unknown>
): Record<string, unknown> {
  const datos: Record<string, unknown> = {}
  for (const c of campos) {
    const v = valores[c.nombre]
    const estaba = c.nombre in propuesto
    if (v === comoTexto(propuesto[c.nombre])) {
      if (estaba) datos[c.nombre] = propuesto[c.nombre]
    } else if (!v.trim()) {
      // Vaciar borra el dato. Una lista vacía es una lista, y una opción sin valor no se manda.
      if (c.tipo === 'lista') datos[c.nombre] = []
      else if (!c.opciones || c.nombre === 'phase_type') datos[c.nombre] = null
    } else if (c.tipo === 'numero') datos[c.nombre] = numero(v)
    else if (c.tipo === 'lista') datos[c.nombre] = lineas(v)
    else datos[c.nombre] = v
  }
  return datos
}
