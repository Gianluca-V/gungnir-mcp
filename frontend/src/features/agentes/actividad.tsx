import { useState } from 'react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Estado, useFechaHora, type KeyAgente } from './comun'

interface Accion {
  id: number
  accion: string
  codigo: number
  objetivo: string | null
  detalle: string | null
  fuera: boolean
  veces: number
  creada_en: string
  ultima_en: string
  engagement_title: string | null
}
interface Pagina {
  datos: Accion[]
  siguiente: number | null
}

const FILTROS = ['todo', 'rechazos', 'fuera'] as const

/** Qué escribió una key y qué se le rechazó, de lo más nuevo a lo más viejo. */
export function Actividad({
  de,
  cerrar,
}: {
  de: KeyAgente
  cerrar: () => void
}) {
  const { t } = useTranslation()
  const [filtro, setFiltro] = useState<(typeof FILTROS)[number]>('todo')
  const consulta = useInfiniteQuery({
    queryKey: ['agentes', 'actividad', de.id, filtro],
    queryFn: ({ pageParam }) => {
      const q = new URLSearchParams()
      if (filtro !== 'todo') q.set('filtro', filtro)
      if (pageParam) q.set('antes', String(pageParam))
      return apiFetch<Pagina>(`/agentes/keys/${de.id}/actividad?${q}`)
    },
    initialPageParam: null as number | null,
    getNextPageParam: (p) => p.siguiente,
  })
  const filas = consulta.data?.pages.flatMap((p) => p.datos) ?? []
  return (
    <Sheet open onOpenChange={(v) => !v && cerrar()}>
      <SheetContent className='w-full gap-0 sm:max-w-xl'>
        <SheetHeader>
          <SheetTitle className='pr-8 break-words'>
            {t('agentes.activity.title', {
              name: de.nombre,
              interpolation: { escapeValue: false },
            })}
          </SheetTitle>
          <SheetDescription>{t('agentes.activity.desc')}</SheetDescription>
        </SheetHeader>
        <div className='px-4 pb-3'>
          <Tabs
            value={filtro}
            onValueChange={(v) => setFiltro(v as typeof filtro)}
          >
            <TabsList>
              {FILTROS.map((f) => (
                <TabsTrigger key={f} value={f}>
                  {t(`agentes.activity.filter_${f}`)}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>
        <div className='min-h-0 flex-1 overflow-y-auto px-4 pb-6'>
          <Estado
            cargando={consulta.isLoading}
            error={consulta.isError && !filas.length}
            reintentar={() => consulta.refetch()}
            vacio={!filas.length}
            textoVacio={t(
              filtro === 'todo'
                ? 'agentes.activity.empty'
                : 'agentes.activity.empty_filter'
            )}
          >
            <ol className='divide-y divide-border'>
              {filas.map((a) => (
                <Fila key={a.id} a={a} />
              ))}
            </ol>
            {consulta.hasNextPage && (
              <Button
                variant='outline'
                className='mt-4 w-full'
                disabled={consulta.isFetchingNextPage}
                onClick={() => consulta.fetchNextPage()}
              >
                {t(
                  consulta.isFetchNextPageError
                    ? 'agentes.retry'
                    : 'agentes.activity.more'
                )}
              </Button>
            )}
          </Estado>
        </div>
      </SheetContent>
    </Sheet>
  )
}

function Fila({ a }: { a: Accion }) {
  const { t } = useTranslation()
  const fecha = useFechaHora()
  const rechazada = a.codigo >= 400
  const resultado = rechazada
    ? 'rejected'
    : a.codigo === 202
      ? 'proposed'
      : 'done'
  return (
    <li className='py-3'>
      <div className='flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1'>
        <p className='flex flex-wrap items-center gap-2 text-sm font-medium'>
          {t(`agentes.activity.action.${a.accion}`)}
          <span
            className={cn(
              'rounded border px-1.5 text-xs font-normal',
              rechazada
                ? 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-400'
                : 'border-border bg-muted text-muted-foreground'
            )}
          >
            {t(`agentes.activity.${resultado}`)}
            {rechazada && ` (${a.codigo})`}
          </span>
          {a.fuera && (
            <span className='rounded border border-amber-500/40 bg-amber-500/10 px-1.5 text-xs font-normal text-amber-800 dark:text-amber-400'>
              {t('agentes.activity.out_of_scope')}
            </span>
          )}
        </p>
        <time
          dateTime={a.ultima_en}
          className='text-xs text-muted-foreground tabular-nums'
        >
          {fecha(a.ultima_en)}
        </time>
      </div>
      {/* Texto plano a propósito: lo escribió un agente. */}
      {a.objetivo && (
        <p className='mt-1 font-mono text-xs break-all'>{a.objetivo}</p>
      )}
      {a.detalle && (
        <p
          className={cn(
            'mt-1 text-xs break-words whitespace-pre-wrap text-muted-foreground',
            !rechazada && 'font-mono break-all'
          )}
        >
          {a.detalle}
        </p>
      )}
      {(a.engagement_title || a.veces > 1) && (
        <p className='mt-1 text-xs text-muted-foreground'>
          {[
            a.engagement_title,
            a.veces > 1 &&
              t('agentes.activity.times', {
                count: a.veces,
                date: fecha(a.creada_en),
                interpolation: { escapeValue: false },
              }),
          ]
            .filter(Boolean)
            .join(' · ')}
        </p>
      )}
    </li>
  )
}
