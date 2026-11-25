import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown } from 'lucide-react'
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
  type Propuesta,
} from './comun'

const texto = (v: unknown) =>
  Array.isArray(v)
    ? v.join('\n')
    : v === null || v === undefined
      ? ''
      : String(v)

export function Propuestas() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const fecha = useFechaHora()
  const { decide } = usePermisosAgentes()
  const [elegidas, setElegidas] = useState<Set<string>>(new Set())
  const [conflicto, setConflicto] = useState<Propuesta | null>(null)
  const [aRechazar, setARechazar] = useState<Propuesta | null>(null)
  const [motivo, setMotivo] = useState('')

  const consulta = useQuery<Propuesta[]>({
    queryKey: ['agentes', 'propuestas'],
    queryFn: () => apiFetch<Propuesta[]>('/agentes/propuestas'),
    refetchInterval: 60_000,
  })
  const filas = consulta.data ?? []
  // Lo que ya se decidió en otro lado deja de contar como elegido.
  const vigentes = filas.filter((p) => elegidas.has(p.id))

  const alTerminar = () => qc.invalidateQueries({ queryKey: ['agentes'] })
  const aprobar = useMutation({
    mutationFn: ({ p, forzar }: { p: Propuesta; forzar: boolean }) =>
      apiFetch(`/agentes/propuestas/${p.id}/aprobar`, {
        method: 'POST',
        body: { forzar },
      }),
    onSuccess: () => {
      setConflicto(null)
      toast.success(t('agentes.proposals.approved'))
    },
    onError: (e: Error, { p, forzar }) => {
      // apiFetch solo entrega el mensaje del error, no el código.
      if (!forzar && e.message.startsWith('El hallazgo cambió')) setConflicto(p)
      else toast.error(e.message)
    },
    onSettled: alTerminar,
  })
  const lote = useMutation({
    mutationFn: (ids: string[]) =>
      apiFetch<{ aprobadas: string[]; errores: { error: string }[] }>(
        '/agentes/propuestas/aprobar-lote',
        { method: 'POST', body: { ids } }
      ),
    onSuccess: (r) => {
      setElegidas(new Set())
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
    onSuccess: () => toast.success(t('agentes.proposals.rejected')),
    onError: (e: Error) => toast.error(e.message),
    onSettled: () => {
      setARechazar(null)
      setMotivo('')
      alTerminar()
    },
  })
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
                onClick={() =>
                  lote.mutate(vigentes.slice(0, 300).map((p) => p.id))
                }
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
            const titulo = texto(p.datos.title) || p.hallazgo_actual || ''
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
                        <span className='text-sm font-medium break-words'>
                          {titulo}
                        </span>
                      </div>
                      <p className='mt-1 text-xs text-muted-foreground'>
                        {t(
                          p.accion === 'crear'
                            ? 'agentes.proposals.new'
                            : 'agentes.proposals.change'
                        )}
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
                      {p.datos.affected_asset != null && (
                        <p className='mt-1 font-mono text-xs break-all'>
                          {texto(p.datos.affected_asset)}
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
                      <div className='flex gap-2'>
                        <Button
                          variant='outline'
                          size='sm'
                          disabled={ocupado}
                          onClick={() => setARechazar(p)}
                        >
                          {t('agentes.proposals.reject')}
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
                    <dl className='mt-3 space-y-3'>
                      {Object.entries(p.datos)
                        .filter(
                          ([k, v]) =>
                            !['title', 'affected_asset', 'severity'].includes(
                              k
                            ) && texto(v)
                        )
                        .map(([k, v]) => (
                          <div key={k}>
                            <dt className='font-mono text-xs text-muted-foreground'>
                              {k}
                            </dt>
                            <dd className='max-h-64 max-w-[75ch] overflow-y-auto text-sm break-words whitespace-pre-wrap'>
                              {texto(v)}
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

      <ConfirmDialog
        open={!!conflicto}
        onOpenChange={(v) => !v && setConflicto(null)}
        title={t('agentes.proposals.conflict_title')}
        desc={t('agentes.proposals.conflict_desc')}
        confirmText={t('agentes.proposals.force')}
        destructive
        isLoading={aprobar.isPending}
        handleConfirm={() =>
          conflicto && aprobar.mutate({ p: conflicto, forzar: true })
        }
      />
      <ConfirmDialog
        open={!!aRechazar}
        onOpenChange={(v) => !v && setARechazar(null)}
        title={t('agentes.proposals.reject_title')}
        desc={texto(aRechazar?.datos.title) || aRechazar?.hallazgo_actual || ''}
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
