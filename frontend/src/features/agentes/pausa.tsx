import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Pause, Play } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useFechaHora, usePermisosAgentes, useResumenAgentes } from './comun'

/** Pausa o reanuda todos los agentes, o uno solo de los engagements. */
export function usePausar(engagementId?: string) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (pausado: boolean) =>
      apiFetch(
        engagementId
          ? `/agentes/engagements/${engagementId}/pausa`
          : '/agentes/pausa',
        { method: 'POST', body: { pausado } }
      ),
    onSuccess: (_r, pausado) =>
      toast.success(
        t(pausado ? 'agentes.pause.paused_ok' : 'agentes.pause.resumed_ok')
      ),
    onError: (e: Error) => toast.error(e.message),
    onSettled: () => qc.invalidateQueries({ queryKey: ['agentes'] }),
  })
}

/** Botón para frenar a todos los agentes. En pausa lo reemplaza el aviso. */
export function BotonPausa() {
  const { t } = useTranslation()
  const { decide } = usePermisosAgentes()
  const { data } = useResumenAgentes()
  const pausar = usePausar()
  const [confirmar, setConfirmar] = useState(false)
  if (!decide || data?.pausa) return null
  return (
    <>
      <Button variant='outline' onClick={() => setConfirmar(true)}>
        <Pause />
        {t('agentes.pause.all')}
      </Button>
      <ConfirmDialog
        open={confirmar}
        onOpenChange={setConfirmar}
        title={t('agentes.pause.all_title')}
        desc={t('agentes.pause.all_desc')}
        confirmText={t('agentes.pause.all')}
        destructive
        isLoading={pausar.isPending}
        handleConfirm={() =>
          pausar.mutate(true, { onSettled: () => setConfirmar(false) })
        }
      />
    </>
  )
}

export function AvisoPausa() {
  const { t } = useTranslation()
  const fecha = useFechaHora()
  const { administraAcceso } = usePermisosAgentes()
  const { data } = useResumenAgentes()
  const pausar = usePausar()
  if (!data?.pausa) return null
  return (
    <div
      role='status'
      className='flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4'
    >
      <div className='min-w-0 flex-1 basis-64'>
        <p className='flex items-center gap-2 text-sm font-semibold text-amber-900 dark:text-amber-200'>
          <Pause className='h-4 w-4 shrink-0' />
          {t('agentes.pause.active_title')}
        </p>
        <p className='mt-1 max-w-[75ch] text-sm text-amber-900 dark:text-amber-200'>
          {t('agentes.pause.active_desc', {
            user: data.pausa.por ?? '-',
            date: fecha(data.pausa.desde),
            interpolation: { escapeValue: false },
          })}
          {!administraAcceso && ` ${t('agentes.pause.who_resumes')}`}
        </p>
      </div>
      {administraAcceso && (
        <Button
          variant='outline'
          disabled={pausar.isPending}
          onClick={() => pausar.mutate(false)}
        >
          <Play />
          {t('agentes.pause.resume')}
        </Button>
      )}
    </div>
  )
}

/** Pausa de un engagement, en su fila. */
export function PausaEngagement({
  id,
  titulo,
  desde,
}: {
  id: string
  titulo: string
  desde: string | null
}) {
  const { t } = useTranslation()
  const fecha = useFechaHora()
  const { decide, administraAcceso } = usePermisosAgentes()
  const pausar = usePausar(id)
  const puede = desde ? administraAcceso : decide
  return (
    <div className='mt-2 flex flex-wrap items-center gap-2'>
      {puede && (
        <Button
          variant='ghost'
          size='sm'
          className='h-7 px-2 text-xs'
          disabled={pausar.isPending}
          aria-label={`${t(desde ? 'agentes.pause.resume' : 'agentes.pause.one')}: ${titulo}`}
          onClick={() => pausar.mutate(!desde)}
        >
          {desde ? <Play /> : <Pause />}
          {t(desde ? 'agentes.pause.resume' : 'agentes.pause.one')}
        </Button>
      )}
      {desde && (
        <span className='max-w-36 text-xs font-medium whitespace-normal text-amber-800 dark:text-amber-400'>
          {t('agentes.pause.since', {
            date: fecha(desde),
            interpolation: { escapeValue: false },
          })}
        </span>
      )}
    </div>
  )
}
