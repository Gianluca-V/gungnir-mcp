import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Pencil, Plus } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { useAuthStore } from '@/stores/auth-store'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Estado, InsigniaNivel, useFechaHora, type KeyAgente } from './comun'
import { DialogoKey } from './dialogo-key'

export function Keys() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const fecha = useFechaHora()
  const miId = useAuthStore((s) => s.auth.user?.id)
  const [dialogo, setDialogo] = useState<{ key: KeyAgente | null } | null>(null)
  const [aRevocar, setARevocar] = useState<KeyAgente | null>(null)

  const consulta = useQuery<KeyAgente[]>({
    queryKey: ['agentes', 'keys'],
    queryFn: () => apiFetch<KeyAgente[]>('/agentes/keys'),
  })
  const revocar = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/agentes/keys/${id}`, { method: 'DELETE' }),
    onSuccess: () => toast.success(t('agentes.keys.revoked_ok')),
    onError: (e: Error) => toast.error(e.message),
    onSettled: () => {
      setARevocar(null)
      qc.invalidateQueries({ queryKey: ['agentes', 'keys'] })
    },
  })

  const filas = consulta.data ?? []
  return (
    <div className='space-y-4'>
      <div className='flex justify-end'>
        <Button size='sm' onClick={() => setDialogo({ key: null })}>
          <Plus />
          {t('agentes.keys.new')}
        </Button>
      </div>
      <Estado
        cargando={consulta.isLoading}
        error={consulta.isError}
        reintentar={() => consulta.refetch()}
        vacio={!filas.length}
        textoVacio={t('agentes.keys.empty')}
      >
        <div className='overflow-x-auto rounded-lg border border-border'>
          <Table>
            <TableHeader>
              <TableRow className='hover:bg-transparent'>
                {(
                  [
                    'name',
                    'level',
                    'engagements',
                    'expires',
                    'last',
                    'state',
                  ] as const
                ).map((c) => (
                  <TableHead key={c} className='text-xs font-semibold'>
                    {t(`agentes.keys.col_${c}`)}
                  </TableHead>
                ))}
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filas.map((k) => {
                const estado = k.revocada_en
                  ? 'revoked'
                  : k.vencida
                    ? 'expired'
                    : 'active'
                return (
                  <TableRow key={k.id}>
                    <TableCell>
                      <div className='text-sm font-medium'>{k.nombre}</div>
                      <div className='text-xs text-muted-foreground'>
                        <span className='font-mono'>{k.prefijo}…</span>
                        {k.user_id !== miId &&
                          ` ${t('agentes.keys.owner', { user: k.username, interpolation: { escapeValue: false } })}`}
                      </div>
                    </TableCell>
                    <TableCell>
                      <InsigniaNivel nivel={k.nivel_max} />
                    </TableCell>
                    <TableCell className='max-w-64 text-sm whitespace-normal'>
                      {k.engagements.map((e) => e.title).join(', ')}
                    </TableCell>
                    <TableCell className='text-xs text-muted-foreground tabular-nums'>
                      {fecha(k.expira_en, false)}
                    </TableCell>
                    <TableCell className='text-xs text-muted-foreground tabular-nums'>
                      {fecha(k.ultimo_uso) || t('agentes.keys.never')}
                    </TableCell>
                    <TableCell
                      className={
                        estado === 'active'
                          ? 'text-xs font-medium text-green-700 dark:text-green-400'
                          : 'text-xs text-muted-foreground'
                      }
                    >
                      {t(`agentes.keys.${estado}`)}
                    </TableCell>
                    <TableCell className='text-right'>
                      {!k.revocada_en && (
                        <>
                          <Button
                            variant='ghost'
                            size='icon'
                            className='size-8'
                            aria-label={`${t('agentes.keys.edit')}: ${k.nombre}`}
                            title={t('agentes.keys.edit')}
                            onClick={() => setDialogo({ key: k })}
                          >
                            <Pencil />
                          </Button>
                          <Button
                            variant='ghost'
                            size='icon'
                            className='size-8 hover:text-destructive'
                            aria-label={`${t('agentes.keys.revoke')}: ${k.nombre}`}
                            title={t('agentes.keys.revoke')}
                            onClick={() => setARevocar(k)}
                          >
                            <Ban />
                          </Button>
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      </Estado>

      {dialogo && (
        <DialogoKey existente={dialogo.key} cerrar={() => setDialogo(null)} />
      )}
      <ConfirmDialog
        open={!!aRevocar}
        onOpenChange={(v) => !v && setARevocar(null)}
        title={t('agentes.keys.revoke_title', {
          name: aRevocar?.nombre ?? '',
          interpolation: { escapeValue: false },
        })}
        desc={t('agentes.keys.revoke_desc')}
        confirmText={t('agentes.keys.revoke')}
        destructive
        isLoading={revocar.isPending}
        handleConfirm={() => aRevocar && revocar.mutate(aRevocar.id)}
      />
    </div>
  )
}
