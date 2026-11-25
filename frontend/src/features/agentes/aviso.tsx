import { Link } from '@tanstack/react-router'
import { Bot, Pause } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { cn } from '@/lib/utils'
import { useResumenAgentes } from './comun'

/** Aviso en la cabecera. Solo aparece si hay algo de los agentes por revisar o si están en pausa. */
export function AvisoAgentes() {
  const { t } = useTranslation()
  const { data } = useResumenAgentes()
  const total = (data?.propuestas ?? 0) + (data?.violaciones ?? 0)
  if (!data || (!total && !data.pausa)) return null
  const texto = [
    data.pausa && t('agentes.pause.active_title'),
    total > 0 &&
      t('agentes.notice', {
        propuestas: data.propuestas,
        violaciones: data.violaciones,
      }),
  ]
    .filter(Boolean)
    .join('. ')
  return (
    <Link
      to='/integraciones/agentes'
      title={texto}
      aria-label={texto}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium tabular-nums focus-visible:ring-2 focus-visible:ring-ring',
        data.violaciones
          ? 'bg-red-700 text-white hover:bg-red-800'
          : 'bg-muted text-foreground hover:bg-accent'
      )}
    >
      {data.pausa ? <Pause className='h-4 w-4' /> : <Bot className='h-4 w-4' />}
      {total > 0 && total}
    </Link>
  )
}
