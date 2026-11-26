/**
 * Cadena de ataque: cómo un hallazgo llevó al siguiente, dibujada de izquierda a derecha. Los equipos van
 * antes de sus hallazgos y las técnicas de la fase, al lado. La lista de relaciones repite el grafo en texto.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { DataSet, Network } from 'vis-network/standalone'
import type { Edge, Node, Options } from 'vis-network'
import { Bot, Loader2, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { buildGraph, orderLinks, RELATIONS, type AttackChain as Chain, type GraphOptions, type Relation } from '@/lib/attack-chain'
import { useTheme } from '@/context/theme-provider'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'

const SEVERITY: Record<string, string> = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#6b7280' }
const MIN_SCALE = 0.75
const RELATION: Record<Relation, string> = { enables: '#dc2626', escalates: '#9333ea', pivots: '#d97706' }

export function AttackChain({ engagementId }: { engagementId: string }) {
  const { t } = useTranslation()
  const { resolvedTheme } = useTheme()
  const dark = resolvedTheme === 'dark'
  const [chain, setChain] = useState<Chain | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [options, setOptions] = useState<GraphOptions>({ showAssets: true, showTechniques: false, showUnlinked: false })
  const [form, setForm] = useState<{ from: string; to: string; relation: Relation; notes: string }>({ from: '', to: '', relation: 'enables', notes: '' })
  const container = useRef<HTMLDivElement>(null)
  const network = useRef<Network | null>(null)

  // Cada cambio de `version` vuelve a pedir la cadena.
  const [version, setVersion] = useState(0)
  const load = useCallback(() => { setLoading(true); setVersion((v) => v + 1) }, [])
  useEffect(() => {
    let vigente = true
    apiFetch<Chain>(`/engagements/${engagementId}/attack-chain`)
      .then((c) => { if (vigente) setChain(c) })
      .catch(() => { if (vigente) toast.error(t('attack_chain.error_load')) })
      .finally(() => { if (vigente) setLoading(false) })
    return () => { vigente = false }
  }, [engagementId, version, t])

  const graph = useMemo(() => (chain ? buildGraph(chain, options) : null), [chain, options])

  useEffect(() => {
    if (!container.current || !graph) return
    const text = dark ? '#e6edf3' : '#0f172a'
    const muted = dark ? '#8b949e' : '#64748b'
    const surface = dark ? '#161b22' : '#ffffff'
    const nodes = new DataSet<Node>(graph.nodes.map((n) => {
      if (n.kind === 'finding') {
        const c = SEVERITY[n.severity ?? 'info'] ?? SEVERITY.info
        return {
          id: n.id, level: n.level, label: n.label.length > 48 ? `${n.label.slice(0, 47)}…` : n.label, title: n.label, shape: 'box',
          color: { background: surface, border: c, highlight: { background: surface, border: c } }, borderWidth: 3,
          font: { color: text, size: 13, face: 'Inter, sans-serif' }, margin: { top: 10, right: 12, bottom: 10, left: 12 }, widthConstraint: { maximum: 220 },
        }
      }
      return {
        id: n.id, level: n.level, label: n.label, shape: n.kind === 'asset' ? 'ellipse' : 'box',
        color: { background: dark ? '#21262d' : '#f1f5f9', border: muted }, borderWidth: 1, shapeProperties: { borderDashes: n.kind === 'technique' ? [4, 3] : false },
        font: { color: muted, size: 12, face: n.kind === 'technique' ? 'Inter, sans-serif' : 'ui-monospace, monospace' },
      }
    }))
    const edges = new DataSet<Edge>(graph.edges.map((e) => e.kind === 'link'
      ? { id: e.id, from: e.from, to: e.to, arrows: 'to', width: 2.5, label: t(`attack_chain.relation.${e.relation}`), color: { color: RELATION[e.relation!], highlight: RELATION[e.relation!] },
          font: { color: text, size: 11, strokeWidth: 3, strokeColor: surface, align: 'middle' } }
      : { id: e.id, from: e.from, to: e.to, arrows: e.kind === 'asset' ? 'to' : undefined, width: 1, dashes: true, color: { color: muted, highlight: muted } }))
    const opts: Options = {
      layout: { hierarchical: { enabled: true, direction: 'LR', sortMethod: 'directed', levelSeparation: 320, nodeSpacing: 90 } },
      physics: { enabled: false },
      interaction: { hover: true, dragNodes: true, zoomView: true },
      edges: { smooth: { enabled: true, type: 'cubicBezier', forceDirection: 'horizontal', roundness: 0.4 } },
    }
    network.current?.destroy()
    const red = new Network(container.current, { nodes, edges }, opts)
    network.current = red
    // Con muchos pasos, encajar todo deja los textos ilegibles: se arranca por el primero a una escala que se lee.
    red.once('afterDrawing', () => {
      red.fit({ animation: false })
      if (red.getScale() >= MIN_SCALE || !graph.nodes.length) return
      const primero = graph.nodes.reduce((a, b) => (b.level < a.level ? b : a))
      const pos = red.getPositions([primero.id])[primero.id]
      const ancho = container.current?.clientWidth ?? 0
      red.moveTo({ scale: MIN_SCALE, position: { x: pos.x + ancho / 2 / MIN_SCALE - 120, y: pos.y } })
    })
    return () => { network.current?.destroy(); network.current = null }
  }, [graph, dark, t])

  async function add() {
    setSaving(true)
    try {
      await apiFetch(`/engagements/${engagementId}/attack-chain`, {
        method: 'POST', body: { from_finding_id: form.from, to_finding_id: form.to, relation: form.relation, notes: form.notes.trim() || undefined },
      })
      setForm({ from: '', to: '', relation: form.relation, notes: '' })
      toast.success(t('attack_chain.added'))
      load()
    } catch (e) { toast.error(e instanceof Error ? e.message : t('attack_chain.error_save')) }
    finally { setSaving(false) }
  }
  async function remove(id: string) {
    try {
      await apiFetch(`/engagements/${engagementId}/attack-chain/${id}`, { method: 'DELETE' })
      toast.success(t('attack_chain.deleted'))
      load()
    } catch (e) { toast.error(e instanceof Error ? e.message : t('attack_chain.error_save')) }
  }

  if (loading && !chain) return <div className='flex justify-center py-16'><Loader2 className='size-5 animate-spin text-muted-foreground' /></div>
  if (!chain) return <Button variant='outline' size='sm' onClick={load}><RefreshCw className='mr-1.5 size-3.5' />{t('attack_chain.retry')}</Button>

  const links = orderLinks(chain.links)
  const finding = (id: string) => chain.findings.find((f) => f.id === id)
  const toggles: [keyof GraphOptions, string][] = [['showAssets', 'show_assets'], ['showTechniques', 'show_techniques'], ['showUnlinked', 'show_unlinked']]

  return (
    <div className='space-y-6'>
      <div className='min-w-0 space-y-3'>
        <div className='flex flex-wrap items-center gap-x-5 gap-y-2'>
          {toggles.map(([k, label]) => (
            <label key={k} className='flex items-center gap-2 text-sm'>
              <Switch checked={options[k]} onCheckedChange={(v) => setOptions({ ...options, [k]: v })} />
              {t(`attack_chain.${label}`)}
            </label>
          ))}
          <Button variant='ghost' size='sm' className='ml-auto' onClick={load} disabled={loading}>
            <RefreshCw className={`mr-1.5 size-3.5 ${loading ? 'animate-spin' : ''}`} />{t('attack_chain.refresh')}
          </Button>
        </div>
        <div className='flex flex-wrap gap-3 text-xs text-muted-foreground' aria-hidden>
          {RELATIONS.map((r) => (
            <span key={r} className='flex items-center gap-1.5'>
              <span className='inline-block h-0.5 w-5' style={{ background: RELATION[r] }} />{t(`attack_chain.relation.${r}`)}
            </span>
          ))}
        </div>
        <div className='relative h-[55svh] min-h-80 rounded-lg border border-border bg-card'>
          <div ref={container} className='absolute inset-0' role='img' aria-label={t('attack_chain.graph_label', { count: links.length })} />
          {!graph?.nodes.length && (
            <p className='absolute inset-0 grid place-items-center p-6 text-center text-sm text-muted-foreground'>
              {t(chain.findings.length ? 'attack_chain.empty' : 'attack_chain.no_findings')}
            </p>
          )}
        </div>
      </div>

      <div className='grid items-start gap-6 lg:grid-cols-[22rem_minmax(0,1fr)]'>
        <form className='space-y-3 rounded-lg border border-border p-4' onSubmit={(e) => { e.preventDefault(); add() }}>
          <h3 className='text-sm font-semibold'>{t('attack_chain.add')}</h3>
          {(['from', 'to'] as const).map((k) => (
            <div key={k} className='space-y-1.5'>
              <Label htmlFor={`chain-${k}`}>{t(`attack_chain.${k}`)}</Label>
              <Select value={form[k]} onValueChange={(v) => setForm({ ...form, [k]: v })}>
                <SelectTrigger id={`chain-${k}`} className='w-full'><SelectValue placeholder={t('attack_chain.pick')} /></SelectTrigger>
                <SelectContent>
                  {chain.findings.filter((f) => f.id !== (k === 'from' ? form.to : form.from)).map((f) => (
                    <SelectItem key={f.id} value={f.id}>{f.title}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ))}
          <div className='space-y-1.5'>
            <Label htmlFor='chain-relation'>{t('attack_chain.relation_label')}</Label>
            <Select value={form.relation} onValueChange={(v) => setForm({ ...form, relation: v as Relation })}>
              <SelectTrigger id='chain-relation' className='w-full'><SelectValue /></SelectTrigger>
              <SelectContent>
                {RELATIONS.map((r) => <SelectItem key={r} value={r}>{t(`attack_chain.relation.${r}`)}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className='space-y-1.5'>
            <Label htmlFor='chain-notes'>{t('attack_chain.notes')}</Label>
            <Textarea id='chain-notes' maxLength={5000} className='min-h-16' value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          </div>
          <Button type='submit' size='sm' className='w-full' disabled={!form.from || !form.to || saving}>
            {saving ? <Loader2 className='mr-1.5 size-3.5 animate-spin' /> : <Plus className='mr-1.5 size-3.5' />}{t('attack_chain.add')}
          </Button>
        </form>

        <section>
          <h3 className='mb-2 text-sm font-semibold'>{t('attack_chain.steps', { count: links.length })}</h3>
          {!links.length ? <p className='text-sm text-muted-foreground'>{t('attack_chain.empty')}</p> : (
            <ol className='space-y-2'>
              {links.map((l) => (
                <li key={l.id} className='rounded-md border border-border p-3 text-sm'>
                  <div className='flex items-start gap-2'>
                    <p className='min-w-0 flex-1 break-words'>
                      <span className='font-medium'>{l.from_title}</span>
                      <span className='mx-1.5 text-xs font-semibold' style={{ color: RELATION[l.relation] }}>{t(`attack_chain.relation.${l.relation}`)}</span>
                      <span className='font-medium'>{l.to_title}</span>
                    </p>
                    <Button variant='ghost' size='icon' className='size-7 shrink-0' aria-label={t('attack_chain.delete')} onClick={() => remove(l.id)}>
                      <Trash2 className='size-3.5' />
                    </Button>
                  </div>
                  {l.notes && <p className='mt-1 text-xs whitespace-pre-wrap text-muted-foreground'>{l.notes}</p>}
                  <p className='mt-1 flex flex-wrap gap-x-3 text-xs text-muted-foreground'>
                    {[finding(l.from_finding_id)?.affected_asset, finding(l.to_finding_id)?.affected_asset].filter(Boolean).join(' → ')}
                    {l.created_by_agent && <span className='inline-flex items-center gap-1'><Bot className='size-3' />{t('attack_chain.by_agent')}</span>}
                  </p>
                </li>
              ))}
            </ol>
          )}
        </section>
      </div>
    </div>
  )
}
