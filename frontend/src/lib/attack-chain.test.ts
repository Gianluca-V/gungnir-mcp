import { describe, expect, it } from 'vitest'
import { buildGraph, hostOf, linksBetween, orderLinks, type AttackChain, type ChainLink } from './attack-chain'

const link = (id: string, from: string, to: string, relation: ChainLink['relation'] = 'enables'): ChainLink => ({
  id, from_finding_id: from, to_finding_id: to, relation, notes: null, created_by_agent: false, from_title: from, to_title: to,
})
const finding = (id: string, affected_asset: string | null, phase_type: string | null = 'exploitation') => ({
  id, title: `Finding ${id}`, severity: 'high', status: 'open', affected_asset, phase_type,
})

const chain: AttackChain = {
  findings: [finding('sqli', 'https://app.example.com:8443/login'), finding('admin', 'app.example.com'), finding('db', '10.0.0.5:3306'), finding('xss', '10.0.0.9')],
  links: [link('2', 'admin', 'db', 'pivots'), link('1', 'sqli', 'admin')],
  techniques: [
    { id: 't1', name: 'Exploit Public-Facing Application', mitre_id: 'T1190', tactic: 'Initial Access', phase_type: 'exploitation' },
    { id: 't2', name: 'Port scan', mitre_id: null, tactic: null, phase_type: 'scanning' },
  ],
}

describe('hostOf', () => {
  it.each([
    ['https://app.example.com:8443/login', 'app.example.com'],
    ['10.0.0.5:3306', '10.0.0.5'],
    ['10.0.0.5:3306/tcp', '10.0.0.5'],
    ['[2001:db8::1]:443', '2001:db8::1'],
    ['2001:db8::1', '2001:db8::1'],
    ['host', 'host'],
    ['  ', null],
    [null, null],
  ])('%s → %s', (a, h) => expect(hostOf(a)).toBe(h))
})

describe('orderLinks', () => {
  it('ordena por cómo avanza el ataque, aunque se hayan cargado al revés', () => {
    expect(orderLinks(chain.links).map((l) => l.id)).toEqual(['1', '2'])
  })
  it('un ciclo que llegara igual no rompe ni pierde relaciones', () => {
    expect(orderLinks([link('a', 'x', 'y'), link('b', 'y', 'x')])).toHaveLength(2)
  })
})

describe('linksBetween', () => {
  it('deja afuera las relaciones con un hallazgo que no se incluye', () => {
    expect(linksBetween(chain.links, ['sqli', 'admin']).map((l) => l.id)).toEqual(['1'])
  })
})

describe('buildGraph', () => {
  const todo = { showAssets: true, showTechniques: true, showUnlinked: false }
  it('solo los hallazgos de la cadena, por nivel, con su equipo antes', () => {
    const g = buildGraph(chain, todo)
    const nivel = Object.fromEntries(g.nodes.map((n) => [n.id, n.level]))
    expect(nivel['f:sqli']).toBe(1)
    expect(nivel['f:admin']).toBe(2)
    expect(nivel['f:db']).toBe(3)
    expect(nivel['f:xss']).toBeUndefined()
    expect(nivel['a:app.example.com']).toBe(0)
    expect(g.edges.filter((e) => e.kind === 'asset').map((e) => e.to).sort()).toEqual(['f:admin', 'f:db', 'f:sqli'])
    expect(g.edges.find((e) => e.id === 'l:2')?.relation).toBe('pivots')
  })
  it('las técnicas se unen a los hallazgos de su fase; sin hallazgos de esa fase no aparecen', () => {
    const g = buildGraph(chain, todo)
    expect(g.nodes.find((n) => n.id === 't:t1')?.label).toBe('T1190 Exploit Public-Facing Application')
    expect(g.nodes.some((n) => n.id === 't:t2')).toBe(false)
  })
  it('se pueden sacar equipos y técnicas, y mostrar los hallazgos sueltos', () => {
    const g = buildGraph(chain, { showAssets: false, showTechniques: false, showUnlinked: true })
    expect(g.nodes.map((n) => n.kind)).toEqual(['finding', 'finding', 'finding', 'finding'])
    expect(g.nodes.find((n) => n.id === 'f:sqli')?.level).toBe(0)
    expect(g.edges.every((e) => e.kind === 'link')).toBe(true)
  })
})
