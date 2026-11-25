import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { DialogFooter } from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { type DetallePropuesta, type EquipoMapa } from './comun'

export const equiposDe = (datos: Record<string, unknown>) =>
  (Array.isArray(datos.equipos) ? datos.equipos : []) as EquipoMapa[]

/** Un equipo propuesto para el Attack Map. Texto plano a propósito: lo escribió un agente. */
export function Equipo({ e }: { e: EquipoMapa }) {
  const { t } = useTranslation()
  const marcas = [
    e.os_type,
    e.comprometido && t('agentes.map.owned'),
    e.desde &&
      t('agentes.map.from', {
        host: e.desde,
        interpolation: { escapeValue: false },
      }),
  ].filter(Boolean)
  return (
    <div className='min-w-0'>
      <p className='font-mono text-sm break-all'>{e.objetivo}</p>
      {marcas.length > 0 && (
        <p className='text-xs break-words text-muted-foreground'>
          {marcas.join(' · ')}
        </p>
      )}
      {!!e.puertos?.length && (
        <ul className='mt-1 max-h-40 overflow-y-auto text-xs'>
          {e.puertos.map((p) => (
            <li key={`${p.puerto}/${p.protocolo}`} className='break-words'>
              <span className='font-mono'>
                {p.puerto}/{p.protocolo}
              </span>{' '}
              {[p.servicio, p.producto, p.version].filter(Boolean).join(' ')}
            </li>
          ))}
        </ul>
      )}
      {e.notas && (
        <p className='mt-1 max-w-[75ch] text-xs break-words whitespace-pre-wrap'>
          {e.notas}
        </p>
      )}
    </div>
  )
}

interface Props {
  detalle: DetallePropuesta
  ocupado: boolean
  cerrar: () => void
  aprobar: (datos: Record<string, unknown>) => void
}

/** Elige qué equipos de la propuesta van al mapa. */
export function FormularioMapa({ detalle, ocupado, cerrar, aprobar }: Props) {
  const { t } = useTranslation()
  const equipos = equiposDe(detalle.datos)
  const [sacados, setSacados] = useState<Set<string>>(new Set())
  const quedan = equipos.filter((e) => !sacados.has(e.objetivo))

  function alternar(objetivo: string, incluir: boolean) {
    const s = new Set(sacados)
    if (incluir) s.delete(objetivo)
    else s.add(objetivo)
    setSacados(s)
  }

  return (
    <>
      <ul className='-mx-1 min-h-0 flex-1 divide-y divide-border overflow-y-auto px-1'>
        {equipos.map((e, i) => (
          <li key={e.objetivo} className='py-3'>
            <Label
              htmlFor={`equipo-${i}`}
              className='flex cursor-pointer items-start gap-3 font-normal'
            >
              <Checkbox
                id={`equipo-${i}`}
                className='mt-1'
                checked={!sacados.has(e.objetivo)}
                disabled={ocupado}
                onCheckedChange={(v) => alternar(e.objetivo, v === true)}
              />
              <Equipo e={e} />
            </Label>
          </li>
        ))}
      </ul>
      <DialogFooter className='sm:items-center'>
        <p className='mr-auto text-xs text-muted-foreground' role='status'>
          {t('agentes.map.kept', {
            kept: quedan.length,
            total: equipos.length,
          })}
        </p>
        <Button variant='outline' disabled={ocupado} onClick={cerrar}>
          {t('confirm.cancel')}
        </Button>
        <Button
          disabled={!quedan.length || ocupado}
          onClick={() => aprobar({ equipos: quedan })}
        >
          {t(
            sacados.size
              ? 'agentes.edit.approve_edited'
              : 'agentes.proposals.approve'
          )}
        </Button>
      </DialogFooter>
    </>
  )
}
