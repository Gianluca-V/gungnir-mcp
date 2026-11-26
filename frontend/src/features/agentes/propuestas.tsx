import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown } from 'lucide-react'
import { type TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { BadgeSeveridad } from '@/features/vulnerabilidades/componentes'
import { type Severidad } from '@/features/vulnerabilidades/comun'
import {
  Estado,
  useFechaHora,
  usePermisosAgentes,
  useResumenAgentes,
  type Propuesta,
} from './comun'
import { SOLO_LECTURA } from './campos'
import { DialogoPropuesta } from './dialogo-propuesta'
import { Equipo, equiposDe } from './mapa'

interface Aprobacion {
  p: Propuesta
  /** Lo corregido. Sin esto se aprueba tal como vino. */
  datos?: Record<string, unknown>
}

function texto(v: unknown): string {
  if (v === null || v === undefined) return ''
  if (Array.isArray(v)) return v.map(texto).join('\n')
  return typeof v === 'object' ? JSON.stringify(v) : String(v)
}

const SIN_ESCAPE = { interpolation: { escapeValue: false } }

/** Qué propone, en una línea. Los textos pueden venir de un agente: van sin interpretar. */
function tituloDe(p: Propuesta, equipos: number, t: TFunction): string {
  const d = p.datos
  switch (p.accion) {
    case 'mapa':
      return t('agentes.map.title', { count: equipos })
    case 'fase':
      return t('agentes.proposals.title_fase', {
        fase: t(`agentes.option.fase.${texto(d.fase)}`, {
          defaultValue: texto(d.fase),
        }),
        ...SIN_ESCAPE,
      })
    case 'fase_custom':
      return t('agentes.proposals.title_fase_custom', {
        nombre: texto(d.fase_nombre),
        ...SIN_ESCAPE,
      })
    case 'resumen':
      return t('agentes.proposals.title_resumen')
    case 'cadena':
      return t('agentes.proposals.title_cadena', {
        origen: texto(d.origen_titulo),
        destino: texto(d.destino_titulo),
        tipo: t(`agentes.option.tipo.${texto(d.tipo)}`, {
          defaultValue: texto(d.tipo),
        }),
        ...SIN_ESCAPE,
      })
    default:
      return texto(d.title) || p.hallazgo_actual || ''
  }
}

export function Propuestas() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const fecha = useFechaHora()
  const { decide } = usePermisosAgentes()
  const [elegidas, setElegidas] = useState<Set<string>>(new Set())
  const [aEditar, setAEditar] = useState<Propuesta | null>(null)
  const [conflicto, setConflicto] = useState<Aprobacion | null>(null)
  const [aRechazar, setARechazar] = useState<Propuesta | null>(null)
  const [motivo, setMotivo] = useState('')

  const consulta = useQuery<Propuesta[]>({
    queryKey: ['agentes', 'propuestas'],
    queryFn: () => apiFetch<Propuesta[]>('/agentes/propuestas'),
    refetchInterval: 60_000,
  })
  const filas = consulta.data ?? []
  const total = useResumenAgentes().data?.propuestas ?? 0
  // Lo que ya se decidió en otro lado deja de contar como elegido.
  const vigentes = filas.filter((p) => elegidas.has(p.id))

  // En el mapa no se pisa lo que ya había: quien aprueba tiene que saberlo.
  const avisarConservados = (n = 0) =>
    n > 0 && toast.info(t('agentes.map.conserved', { count: n }))
  const alTerminar = () => qc.invalidateQueries({ queryKey: ['agentes'] })
  const aprobar = useMutation({
    mutationFn: ({ p, datos, forzar }: Aprobacion & { forzar: boolean }) =>
      apiFetch<{ resultado?: { conservados: unknown[] } }>(
        `/agentes/propuestas/${p.id}/aprobar`,
        { method: 'POST', body: { forzar, datos } }
      ),
    onSuccess: (r) => {
      avisarConservados(r.resultado?.conservados.length)
      setConflicto(null)
      setAEditar(null)
      toast.success(t('agentes.proposals.approved'))
    },
    onError: (
      e: Error & { datos?: { conflicto?: boolean } },
      { p, datos, forzar }
    ) => {
      if (!forzar && e.datos?.conflicto) setConflicto({ p, datos })
      else toast.error(e.message)
    },
    onSettled: alTerminar,
  })
  const lote = useMutation({
    mutationFn: (ids: string[]) =>
      apiFetch<{
        aprobadas: string[]
        errores: { error: string }[]
        conservados?: number
      }>('/agentes/propuestas/aprobar-lote', { method: 'POST', body: { ids } }),
    onSuccess: (r) => {
      setElegidas(new Set())
      avisarConservados(r.conservados)
      if (r.aprobadas.length)
        toast.success(
          t('agentes.proposals.batch_ok', { count: r.aprobadas.length })
        )
      if (r.errores.length)
        toast.error(
          t('agentes.proposals.batch_errors', {
            count: r.errores.length,
            error: r.errores[0].error,
            interpolation: { escapeValue: false },
          })
        )
    },
    onError: (e: Error) => toast.error(e.message),
    onSettled: alTerminar,
  })
  const rechazar = useMutation({
    mutationFn: (p: Propuesta) =>
      apiFetch(`/agentes/propuestas/${p.id}/rechazar`, {
        method: 'POST',
        body: { motivo },
      }),
    onSuccess: () => {
      cerrarRechazo()
      toast.success(t('agentes.proposals.rejected'))
    },
    onError: (e: Error) => toast.error(e.message),
    onSettled: alTerminar,
  })
  function cerrarRechazo() {
    setARechazar(null)
    setMotivo('')
  }
  const ocupado = aprobar.isPending || lote.isPending || rechazar.isPending

  function alternar(id: string, v: boolean) {
    const s = new Set(elegidas)
    if (v) s.add(id)
    else s.delete(id)
    setElegidas(s)
  }

  return (
    <div className='space-y-4'>
      <Estado
        cargando={consulta.isLoading}
        error={consulta.isError}
        reintentar={() => consulta.refetch()}
        vacio={!filas.length}
        textoVacio={
          <>
            <p className='font-medium text-foreground'>
              {t('agentes.proposals.empty')}
            </p>
            <p className='mt-1'>{t('agentes.proposals.empty_hint')}</p>
          </>
        }
      >
        {total > filas.length && (
          <p role='status' className='text-sm text-muted-foreground'>
            {t('agentes.proposals.truncated', { shown: filas.length, total })}
          </p>
        )}
        {decide && (
          <div className='flex min-h-9 items-center justify-between gap-3'>
            <Label className='flex cursor-pointer items-center gap-2 font-normal'>
              <Checkbox
                checked={
                  vigentes.length === filas.length
                    ? true
                    : vigentes.length
                      ? 'indeterminate'
                      : false
                }
                onCheckedChange={(v) =>
                  setElegidas(
                    v === true ? new Set(filas.map((p) => p.id)) : new Set()
                  )
                }
              />
              {t('agentes.proposals.select_all')}
            </Label>
            {vigentes.length > 0 && (
              <Button
                size='sm'
                disabled={ocupado}
                onClick={() => lote.mutate(vigentes.map((p) => p.id))}
              >
                {t('agentes.proposals.approve_selected', {
                  count: vigentes.length,
                })}
              </Button>
            )}
          </div>
        )}
        <ul className='divide-y divide-border rounded-lg border border-border'>
          {filas.map((p) => {
            const equipos = equiposDe(p.datos)
            const titulo = tituloDe(p, equipos.length, t)
            const sev = p.datos.severity as Severidad | undefined
            return (
              <li key={p.id} className='flex gap-3 p-4'>
                {decide && (
                  <Checkbox
                    className='mt-1'
                    checked={elegidas.has(p.id)}
                    onCheckedChange={(v) => alternar(p.id, v === true)}
                    aria-label={t('agentes.proposals.select', {
                      title: titulo,
                      interpolation: { escapeValue: false },
                    })}
                  />
                )}
                <Collapsible className='min-w-0 flex-1'>
                  <div className='flex flex-wrap items-start justify-between gap-3'>
                    <div className='min-w-0 flex-1 basis-64'>
                      <div className='flex flex-wrap items-center gap-2'>
                        {sev && <BadgeSeveridad s={sev} />}
                        {p.accion === 'retest' && (
                          <span className='rounded border bg-muted px-1.5 text-xs'>
                            {t(
                              `agentes.option.resultado.${texto(p.datos.resultado)}`,
                              { defaultValue: texto(p.datos.resultado) }
                            )}
                          </span>
                        )}
                        <span className='text-sm font-medium break-words'>
                          {titulo}
                        </span>
                      </div>
                      <p className='mt-1 text-xs text-muted-foreground'>
                        {t(`agentes.proposals.kind_${p.accion}`)}
                        {' · '}
                        {p.engagement_title}
                        {' · '}
                        {t('agentes.proposals.by', {
                          key: p.key_nombre,
                          interpolation: { escapeValue: false },
                        })}
                        {' · '}
                        {fecha(p.creada_en)}
                      </p>
                      {(p.datos.affected_asset ?? p.datos.objetivo) != null && (
                        <p className='mt-1 font-mono text-xs break-all'>
                          {texto(p.datos.affected_asset ?? p.datos.objetivo)}
                        </p>
                      )}
                      {p.accion === 'actualizar' && p.hallazgo_actual && (
                        <p className='mt-1 text-xs'>
                          {t('agentes.proposals.target', {
                            title: p.hallazgo_actual,
                            interpolation: { escapeValue: false },
                          })}
                        </p>
                      )}
                    </div>
                    {decide && (
                      <div className='flex flex-wrap gap-2'>
                        <Button
                          variant='outline'
                          size='sm'
                          disabled={ocupado}
                          onClick={() => setARechazar(p)}
                        >
                          {t('agentes.proposals.reject')}
                        </Button>
                        <Button
                          variant='outline'
                          size='sm'
                          disabled={ocupado}
                          onClick={() => setAEditar(p)}
                        >
                          {t('agentes.edit.open')}
                        </Button>
                        <Button
                          size='sm'
                          disabled={ocupado}
                          onClick={() => aprobar.mutate({ p, forzar: false })}
                        >
                          {t('agentes.proposals.approve')}
                        </Button>
                      </div>
                    )}
                  </div>
                  <CollapsibleTrigger className='group mt-2 inline-flex items-center gap-1 rounded text-xs text-muted-foreground hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring'>
                    <ChevronDown className='h-3.5 w-3.5 transition-transform group-data-[state=open]:rotate-180' />
                    {t('agentes.proposals.details')}
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    {/* Texto plano a propósito: lo escribió un agente. */}
                    {p.accion === 'mapa' && (
                      <ul className='mt-3 space-y-3'>
                        {equipos.map((e) => (
                          <li key={e.objetivo}>
                            <Equipo e={e} />
                          </li>
                        ))}
                      </ul>
                    )}
                    <dl className='mt-3 space-y-3'>
                      {Object.entries(p.datos)
                        .filter(
                          ([k]) =>
                            ![
                              'title',
                              'affected_asset',
                              'severity',
                              'resultado',
                              'objetivo',
                              'equipos',
                            ].includes(k) && !SOLO_LECTURA.has(k)
                        )
                        .map(([k, v]) => (
                          <div key={k}>
                            <dt className='font-mono text-xs text-muted-foreground'>
                              {k}
                            </dt>
                            <dd className='max-h-64 max-w-[75ch] overflow-y-auto text-sm break-words whitespace-pre-wrap'>
                              {texto(v) || (
                                <em className='text-muted-foreground'>
                                  {t('agentes.proposals.empty_value')}
                                </em>
                              )}
                            </dd>
                          </div>
                        ))}
                    </dl>
                  </CollapsibleContent>
                </Collapsible>
              </li>
            )
          })}
        </ul>
      </Estado>

      {aEditar && (
        <DialogoPropuesta
          key={aEditar.id}
          propuesta={aEditar}
          ocupado={aprobar.isPending}
          cerrar={() => setAEditar(null)}
          aprobar={(datos) =>
            aprobar.mutate({ p: aEditar, datos, forzar: false })
          }
        />
      )}
      <ConfirmDialog
        open={!!conflicto}
        onOpenChange={(v) => !v && setConflicto(null)}
        title={t('agentes.proposals.conflict_title')}
        desc={t('agentes.proposals.conflict_desc')}
        confirmText={t('agentes.proposals.force')}
        destructive
        isLoading={aprobar.isPending}
        handleConfirm={() =>
          conflicto && aprobar.mutate({ ...conflicto, forzar: true })
        }
      />
      <ConfirmDialog
        open={!!aRechazar}
        onOpenChange={(v) => !v && cerrarRechazo()}
        title={t('agentes.proposals.reject_title')}
        desc={
          texto(aRechazar?.datos.title) ||
          aRechazar?.hallazgo_actual ||
          (aRechazar &&
            equiposDe(aRechazar.datos)
              .map((e) => e.objetivo)
              .join(', ')) ||
          ''
        }
        confirmText={t('agentes.proposals.reject')}
        destructive
        isLoading={rechazar.isPending}
        handleConfirm={() => aRechazar && rechazar.mutate(aRechazar)}
      >
        <div className='space-y-1.5'>
          <Label htmlFor='motivo-rechazo'>
            {t('agentes.proposals.reject_reason')}
          </Label>
          <Textarea
            id='motivo-rechazo'
            value={motivo}
            maxLength={1000}
            onChange={(e) => setMotivo(e.target.value)}
          />
        </div>
      </ConfirmDialog>
    </div>
  )
}
