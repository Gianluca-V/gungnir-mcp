/**
 * Cadena de ataque: hallazgos unidos por cómo uno lleva al otro. Lógica sin dibujo, compartida por el grafo
 * del workspace y el informe PDF.
 */

export type Relation = 'enables' | 'escalates' | 'pivots'

export interface ChainFinding {
  id: string
  title: string
  severity: string
  status: string
  affected_asset: string | null
  phase_type: string | null
}

export interface ChainLink {
  id: string
  from_finding_id: string
  to_finding_id: string
  relation: Relation
  notes: string | null
  created_by_agent: boolean
  from_title: string
  to_title: string
}

export interface ChainTechnique {
  id: string
  name: string
  mitre_id: string | null
  tactic: string | null
  phase_type: string | null
}

export interface AttackChain {
  findings: ChainFinding[]
  links: ChainLink[]
  techniques: ChainTechnique[]
}

export const RELATIONS: Relation[] = ['enables', 'escalates', 'pivots']

/** El equipo de un activo: sin esquema, ruta ni puerto. "https://app.x.com:8443/login" → "app.x.com". */
export function hostOf(asset: string | null): string | null {
  const s = asset?.trim()
  if (!s) return null
  const sinEsquema = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
  const sinRuta = sinEsquema.split(/[/?#]/)[0]
  // [IPv6]:puerto, o host:puerto con un solo ":"; una IPv6 sola queda entera.
  const v6 = /^\[([^\]]+)\]/.exec(sinRuta)
  if (v6) return v6[1]
  return (sinRuta.split(':').length === 2 ? sinRuta.split(':')[0] : sinRuta) || null
}

/**
 * Las relaciones en orden de ataque: primero las que salen de hallazgos a los que no se llega desde otro.
 * La cadena no tiene ciclos (lo controla el backend); si llegara uno, lo que queda va al final.
 */
export function orderLinks(links: ChainLink[]): ChainLink[] {
  const entran = new Map<string, number>()
  for (const l of links) {
    entran.set(l.to_finding_id, (entran.get(l.to_finding_id) ?? 0) + 1)
    if (!entran.has(l.from_finding_id)) entran.set(l.from_finding_id, 0)
  }
  const nivel = new Map<string, number>()
  const cola = [...entran].filter(([, n]) => n === 0).map(([id]) => id)
  for (const id of cola) nivel.set(id, 0)
  for (let i = 0; i < cola.length; i++) {
    const id = cola[i]
    for (const l of links.filter((x) => x.from_finding_id === id)) {
      nivel.set(l.to_finding_id, Math.max(nivel.get(l.to_finding_id) ?? 0, (nivel.get(id) ?? 0) + 1))
      const resta = (entran.get(l.to_finding_id) ?? 1) - 1
      entran.set(l.to_finding_id, resta)
      if (resta === 0) cola.push(l.to_finding_id)
    }
  }
  const de = (l: ChainLink) => nivel.get(l.from_finding_id) ?? Number.MAX_SAFE_INTEGER
  return [...links].sort((a, b) => de(a) - de(b))
}

/** Solo las relaciones entre hallazgos que se incluyen (por ejemplo, en un informe de abiertos). */
export function linksBetween(links: ChainLink[], findingIds: Iterable<string>): ChainLink[] {
  const ids = new Set(findingIds)
  return links.filter((l) => ids.has(l.from_finding_id) && ids.has(l.to_finding_id))
}

export interface GraphOptions {
  showAssets: boolean
  showTechniques: boolean
  showUnlinked: boolean
}

export interface GraphNode {
  id: string
  kind: 'finding' | 'asset' | 'technique'
  label: string
  severity?: string
  level: number
}

export interface GraphEdge {
  id: string
  from: string
  to: string
  kind: 'link' | 'asset' | 'technique'
  relation?: Relation
}

/**
 * Nodos y aristas del grafo. Los hallazgos van por nivel de la cadena; su equipo, un nivel antes que el
 * primero de ellos; las técnicas de su fase, junto al hallazgo.
 */
export function buildGraph(chain: AttackChain, o: GraphOptions): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const enCadena = new Set(chain.links.flatMap((l) => [l.from_finding_id, l.to_finding_id]))
  const findings = chain.findings.filter((f) => o.showUnlinked || enCadena.has(f.id))
  const ids = new Set(findings.map((f) => f.id))
  const links = linksBetween(chain.links, ids)

  // Nivel de cada hallazgo: el camino más largo que llega hasta él.
  const nivel = new Map(findings.map((f) => [f.id, 0]))
  for (const l of orderLinks(links)) nivel.set(l.to_finding_id, Math.max(nivel.get(l.to_finding_id) ?? 0, (nivel.get(l.from_finding_id) ?? 0) + 1))
  const base = o.showAssets ? 1 : 0

  const nodes: GraphNode[] = findings.map((f) => ({ id: `f:${f.id}`, kind: 'finding', label: f.title, severity: f.severity, level: (nivel.get(f.id) ?? 0) + base }))
  const edges: GraphEdge[] = links.map((l) => ({ id: `l:${l.id}`, from: `f:${l.from_finding_id}`, to: `f:${l.to_finding_id}`, kind: 'link', relation: l.relation }))

  if (o.showAssets) {
    const porEquipo = new Map<string, ChainFinding[]>()
    for (const f of findings) {
      const h = hostOf(f.affected_asset)
      if (h) porEquipo.set(h, [...(porEquipo.get(h) ?? []), f])
    }
    for (const [h, fs] of porEquipo) {
      nodes.push({ id: `a:${h}`, kind: 'asset', label: h, level: Math.min(...fs.map((f) => (nivel.get(f.id) ?? 0) + base)) - 1 })
      for (const f of fs) edges.push({ id: `a:${h}>${f.id}`, from: `a:${h}`, to: `f:${f.id}`, kind: 'asset' })
    }
  }

  if (o.showTechniques) {
    for (const t of chain.techniques) {
      const suyos = findings.filter((f) => t.phase_type && f.phase_type === t.phase_type)
      if (!suyos.length) continue
      nodes.push({ id: `t:${t.id}`, kind: 'technique', label: t.mitre_id ? `${t.mitre_id} ${t.name}` : t.name, level: Math.min(...suyos.map((f) => (nivel.get(f.id) ?? 0) + base)) })
      for (const f of suyos) edges.push({ id: `t:${t.id}>${f.id}`, from: `t:${t.id}`, to: `f:${f.id}`, kind: 'technique' })
    }
  }
  return { nodes, edges }
}
