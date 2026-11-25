import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Estado,
  InsigniaNivel,
  NIVELES,
  usePermisosAgentes,
  type EngagementAcceso,
  type Nivel,
} from './comun'

type Cambio = Pick<EngagementAcceso, 'id' | 'nivel_max' | 'mostrar_sensibles'>

export function Accesos() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { administraAcceso } = usePermisosAgentes()
  // Lo que da más poder o muestra datos se confirma antes de aplicarse.
  const [porConfirmar, setPorConfirmar] = useState<{
    cual: 'total' | 'sensitive'
    titulo: string
    cambio: Cambio
  } | null>(null)

  const consulta = useQuery<EngagementAcceso[]>({
    queryKey: ['agentes', 'engagements'],
    queryFn: () => apiFetch<EngagementAcceso[]>('/agentes/engagements'),
  })
  const guardar = useMutation({
    mutationFn: ({ id, ...body }: Cambio) =>
      apiFetch(`/agentes/engagements/${id}`, { method: 'PUT', body }),
    onSuccess: () => toast.success(t('agentes.access.saved')),
    onError: (e: Error) => toast.error(e.message),
    onSettled: () => {
      setPorConfirmar(null)
      qc.invalidateQueries({ queryKey: ['agentes', 'engagements'] })
    },
  })

  function cambiar(e: EngagementAcceso, parte: Partial<Cambio>) {
    const cambio = {
      id: e.id,
      nivel_max: e.nivel_max,
      mostrar_sensibles: e.mostrar_sensibles,
      ...parte,
    }
    if (parte.nivel_max === 'total')
      setPorConfirmar({ cual: 'total', titulo: e.title, cambio })
    else if (parte.mostrar_sensibles)
      setPorConfirmar({ cual: 'sensitive', titulo: e.title, cambio })
    else guardar.mutate(cambio)
  }

  const filas = consulta.data ?? []
  return (
    <div className='space-y-4'>
      <p className='max-w-[75ch] text-sm text-muted-foreground'>
        {t('agentes.access.intro')}
        {!administraAcceso && ` ${t('agentes.access.read_only')}`}
      </p>
      <Estado
        cargando={consulta.isLoading}
        error={consulta.isError}
        reintentar={() => consulta.refetch()}
        vacio={!filas.length}
        textoVacio={t('agentes.access.empty')}
      >
        <div className='overflow-x-auto rounded-lg border border-border'>
          <Table>
            <TableHeader>
              <TableRow className='hover:bg-transparent'>
                <TableHead className='text-xs font-semibold'>
                  {t('agentes.access.col_engagement')}
                </TableHead>
                <TableHead className='text-xs font-semibold'>
                  {t('agentes.access.col_scope')}
                </TableHead>
                <TableHead className='text-xs font-semibold'>
                  {t('agentes.access.col_level')}
                </TableHead>
                <TableHead className='text-xs font-semibold'>
                  {t('agentes.access.col_sensitive')}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filas.map((e) => {
                const cerrado = ['delivered', 'archived'].includes(e.status)
                return (
                  <TableRow key={e.id}>
                    <TableCell className='min-w-48 whitespace-normal'>
                      <div className='text-sm font-medium'>{e.title}</div>
                      <div className='text-xs text-muted-foreground'>
                        {e.client_name}
                      </div>
                    </TableCell>
                    <TableCell className='text-sm whitespace-normal tabular-nums'>
                      {Number(e.en_alcance) || (
                        <span className='text-xs text-amber-800 dark:text-amber-400'>
                          {t('agentes.access.no_scope')}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {administraAcceso ? (
                        <Select
                          value={e.nivel_max}
                          onValueChange={(v) =>
                            cambiar(e, { nivel_max: v as Nivel })
                          }
                        >
                          <SelectTrigger
                            size='sm'
                            className='w-36 text-sm'
                            aria-label={`${t('agentes.access.col_level')}: ${e.title}`}
                            disabled={guardar.isPending}
                          >
                            <SelectValue>
                              {t(`agentes.level.${e.nivel_max}`)}
                            </SelectValue>
                          </SelectTrigger>
                          <SelectContent>
                            {NIVELES.map((n) => (
                              <SelectItem key={n} value={n}>
                                <span className='flex flex-col items-start'>
                                  <span className='text-sm'>
                                    {t(`agentes.level.${n}`)}
                                  </span>
                                  <span className='text-xs text-muted-foreground'>
                                    {t(`agentes.level_desc.${n}`)}
                                  </span>
                                </span>
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : (
                        <InsigniaNivel nivel={e.nivel_max} />
                      )}
                      {cerrado && e.nivel_max !== 'ninguno' && (
                        <div className='mt-1 text-xs text-muted-foreground'>
                          {t('agentes.access.closed')}
                        </div>
                      )}
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={e.mostrar_sensibles}
                        disabled={
                          !administraAcceso ||
                          guardar.isPending ||
                          e.nivel_max === 'ninguno'
                        }
                        onCheckedChange={(v) =>
                          cambiar(e, { mostrar_sensibles: v })
                        }
                        aria-label={`${t('agentes.access.col_sensitive')}: ${e.title}`}
                      />
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      </Estado>

      <ConfirmDialog
        open={!!porConfirmar}
        onOpenChange={(v) => !v && setPorConfirmar(null)}
        title={t(`agentes.access.${porConfirmar?.cual ?? 'total'}_title`)}
        desc={t(`agentes.access.${porConfirmar?.cual ?? 'total'}_desc`, {
          title: porConfirmar?.titulo ?? '',
          interpolation: { escapeValue: false },
        })}
        confirmText={t(
          `agentes.access.${porConfirmar?.cual ?? 'total'}_confirm`
        )}
        destructive
        isLoading={guardar.isPending}
        handleConfirm={() =>
          porConfirmar && guardar.mutate(porConfirmar.cambio)
        }
      />
    </div>
  )
}
