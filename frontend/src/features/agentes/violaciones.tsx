import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Estado,
  useFechaHora,
  usePermisosAgentes,
  type Violacion,
} from './comun'

export function Violaciones() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const fecha = useFechaHora()
  const { decide } = usePermisosAgentes()
  const [todas, setTodas] = useState(false)

  const consulta = useQuery<Violacion[]>({
    queryKey: ['agentes', 'violaciones', todas],
    queryFn: () =>
      apiFetch<Violacion[]>(`/agentes/violaciones${todas ? '?todas=1' : ''}`),
    refetchInterval: 60_000,
  })
  const revisar = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/agentes/violaciones/${id}/revisar`, { method: 'POST' }),
    onSuccess: () => toast.success(t('agentes.violations.done')),
    onError: (e: Error) => toast.error(e.message),
    onSettled: () => qc.invalidateQueries({ queryKey: ['agentes'] }),
  })

  const filas = consulta.data ?? []
  return (
    <div className='space-y-4'>
      <Label className='flex w-fit cursor-pointer items-center gap-2 font-normal'>
        <Switch checked={todas} onCheckedChange={setTodas} />
        {t('agentes.violations.show_all')}
      </Label>
      <Estado
        cargando={consulta.isLoading}
        error={consulta.isError}
        reintentar={() => consulta.refetch()}
        vacio={!filas.length}
        textoVacio={t('agentes.violations.empty')}
      >
        <ul className='divide-y divide-border rounded-lg border border-border'>
          {filas.map((v) => (
            <li
              key={v.id}
              className='flex flex-wrap items-start justify-between gap-3 p-4'
            >
              <div className='min-w-0 flex-1'>
                <p className='font-mono text-sm font-medium break-all'>
                  {v.objetivo}
                </p>
                <p className='mt-1 max-w-[75ch] text-sm break-words'>
                  {v.motivo}
                </p>
                {v.command && (
                  <pre className='mt-2 max-h-32 overflow-auto rounded-md border bg-muted p-2 font-mono text-xs break-all whitespace-pre-wrap'>
                    {v.command}
                  </pre>
                )}
                <p className='mt-2 text-xs text-muted-foreground'>
                  {t(`agentes.violations.type.${v.tipo}`)}
                  {' · '}
                  {v.engagement_title}
                  {' · '}
                  {t('agentes.proposals.by', {
                    key: v.key_nombre,
                    interpolation: { escapeValue: false },
                  })}
                  {' · '}
                  {fecha(v.creada_en)}
                </p>
              </div>
              {v.revisada_en ? (
                <span className='text-xs text-muted-foreground'>
                  {t('agentes.violations.reviewed_by', {
                    user: v.revisada_por_nombre ?? '-',
                    interpolation: { escapeValue: false },
                  })}
                </span>
              ) : (
                decide && (
                  <Button
                    variant='outline'
                    size='sm'
                    disabled={revisar.isPending}
                    onClick={() => revisar.mutate(v.id)}
                  >
                    {t('agentes.violations.reviewed')}
                  </Button>
                )
              )}
            </li>
          ))}
        </ul>
      </Estado>
    </div>
  )
}
