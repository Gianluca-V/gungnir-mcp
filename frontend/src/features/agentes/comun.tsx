import { type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Loader2 } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { useAuthStore } from '@/stores/auth-store'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'

export const NIVELES = [
  'ninguno',
  'lectura',
  'propuesta',
  'escritura',
  'total',
] as const
export type Nivel = (typeof NIVELES)[number]
export const NIVELES_KEY = NIVELES.slice(1)

export interface EngagementAcceso {
  id: string
  title: string
  client_name: string
  status: string
  nivel_max: Nivel
  mostrar_sensibles: boolean
  en_alcance: number
  pausado_en: string | null
}

export interface KeyAgente {
  id: string
  nombre: string
  prefijo: string
  nivel_max: Nivel
  expira_en: string
  vencida: boolean
  revocada_en: string | null
  ultimo_uso: string | null
  username: string
  user_id: string
  engagements: { id: string; title: string }[]
}

export interface Propuesta {
  id: string
  engagement_title: string
  key_nombre: string
  accion: 'crear' | 'actualizar'
  hallazgo_actual: string | null
  datos: Record<string, unknown>
  creada_en: string
}

export interface Violacion {
  id: string
  engagement_title: string
  key_nombre: string
  tipo: 'log' | 'hallazgo' | 'importacion'
  objetivo: string
  motivo: string
  command: string | null
  creada_en: string
  revisada_en: string | null
  revisada_por_nombre: string | null
}

export interface Resumen {
  propuestas: number
  violaciones: number
  pausa: { desde: string; por: string | null } | null
}

const NIVEL_CLASE: Record<Nivel, string> = {
  ninguno: 'border-border bg-muted text-muted-foreground',
  lectura: 'border-blue-500/30 bg-blue-500/10 text-blue-700 dark:text-blue-400',
  propuesta:
    'border-green-500/30 bg-green-500/10 text-green-700 dark:text-green-400',
  escritura:
    'border-amber-500/30 bg-amber-500/10 text-amber-800 dark:text-amber-400',
  total: 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400',
}

export function InsigniaNivel({ nivel }: { nivel: Nivel }) {
  const { t } = useTranslation()
  return (
    <span
      className={cn(
        'inline-flex rounded border px-1.5 py-0.5 text-xs font-medium',
        NIVEL_CLASE[nivel]
      )}
    >
      {t(`agentes.level.${nivel}`)}
    </span>
  )
}

export function usePermisosAgentes() {
  const rol = useAuthStore((s) => s.auth.user?.role) ?? ''
  return {
    rol,
    administraAcceso: ['admin', 'auditor'].includes(rol),
    decide: ['admin', 'auditor', 'pentester'].includes(rol),
  }
}

export function useFechaHora() {
  const { i18n } = useTranslation()
  return (v: string | null, conHora = true) =>
    v
      ? new Date(v).toLocaleString(
          i18n.language === 'en' ? 'en-US' : 'es-AR',
          conHora
            ? { dateStyle: 'short', timeStyle: 'short' }
            : { dateStyle: 'short' }
        )
      : ''
}

/** Propuestas y acciones fuera de alcance por revisar. Se consulta cada minuto. */
export function useResumenAgentes() {
  return useQuery<Resumen>({
    queryKey: ['agentes', 'resumen'],
    queryFn: () => apiFetch<Resumen>('/agentes/resumen'),
    refetchInterval: 60_000,
  })
}

interface EstadoProps {
  cargando: boolean
  error: boolean
  reintentar: () => void
  vacio: boolean
  textoVacio: ReactNode
  children: ReactNode
}

/** Carga, error y vacío, iguales en las cuatro pestañas. */
export function Estado({
  cargando,
  error,
  reintentar,
  vacio,
  textoVacio,
  children,
}: EstadoProps) {
  const { t } = useTranslation()
  if (cargando)
    return (
      <div
        role='status'
        className='flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground'
      >
        <Loader2 className='h-4 w-4 animate-spin' />
        {t('common.loading')}
      </div>
    )
  if (error)
    return (
      <div
        role='alert'
        className='flex flex-col items-center gap-3 py-12 text-sm'
      >
        {t('agentes.load_error')}
        <Button variant='outline' size='sm' onClick={reintentar}>
          {t('agentes.retry')}
        </Button>
      </div>
    )
  if (vacio)
    return (
      <div className='py-12 text-center text-sm text-muted-foreground'>
        {textoVacio}
      </div>
    )
  return children
}
