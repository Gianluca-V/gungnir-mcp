import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { apiFetch } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import {
  armarDatos,
  CAMPOS,
  CAMPOS_ALTA,
  CAMPOS_RETEST,
  comoTexto,
  errorDe,
  VACIABLES,
  type Campo,
} from './campos'
import { Estado, type DetallePropuesta, type Propuesta } from './comun'

interface Props {
  propuesta: Propuesta
  ocupado: boolean
  cerrar: () => void
  aprobar: (datos: Record<string, unknown>) => void
}

/** Corrige una propuesta y la aprueba. En un cambio, compara con el valor actual y deja sacar campos. */
export function DialogoPropuesta(props: Props) {
  const { t } = useTranslation()
  const { propuesta, ocupado, cerrar } = props
  // Si un refresco falla con el formulario a la vista, se sigue con lo que había: lo escrito no se pierde.
  const consulta = useQuery<DetallePropuesta>({
    queryKey: ['agentes', 'propuesta', propuesta.id],
    queryFn: () =>
      apiFetch<DetallePropuesta>(`/agentes/propuestas/${propuesta.id}`),
    staleTime: Infinity,
    gcTime: 0,
  })
  return (
    <Dialog open onOpenChange={(v) => !v && !ocupado && cerrar()}>
      {/* Un clic afuera no descarta lo que se está corrigiendo. */}
      <DialogContent
        className='flex max-h-[90svh] flex-col sm:max-w-3xl'
        onInteractOutside={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{t('agentes.edit.title')}</DialogTitle>
          <DialogDescription>
            {t(`agentes.edit.desc_${propuesta.accion}`)}
          </DialogDescription>
        </DialogHeader>
        <Estado
          cargando={consulta.isLoading}
          error={consulta.isError && !consulta.data}
          reintentar={() => consulta.refetch()}
          vacio={false}
          textoVacio={null}
        >
          {consulta.data && <Formulario {...props} detalle={consulta.data} />}
        </Estado>
      </DialogContent>
    </Dialog>
  )
}

function Formulario({
  detalle,
  ocupado,
  cerrar,
  aprobar,
}: Props & { detalle: DetallePropuesta }) {
  const { t } = useTranslation()
  const alta = detalle.accion === 'crear'
  const seSacan = detalle.accion === 'actualizar'
  const posibles =
    detalle.accion === 'retest'
      ? CAMPOS_RETEST
      : CAMPOS.filter(
          (c) =>
            c.nombre in detalle.datos || (alta && CAMPOS_ALTA.has(c.nombre))
        )
  const [valores, setValores] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      posibles.map((c) => [c.nombre, comoTexto(detalle.datos[c.nombre])])
    )
  )
  // Con "corregido" la severidad queda en informativa: no se elige.
  const campos = posibles.filter(
    (c) => c.nombre !== 'retest_severity' || valores.resultado !== 'passed'
  )
  const [sacados, setSacados] = useState<Set<string>>(new Set())
  const vigentes = campos.filter((c) => !sacados.has(c.nombre))
  const errores = Object.fromEntries(
    vigentes.map((c) => [c.nombre, errorDe(c, valores[c.nombre])])
  )
  const editado = (c: Campo) =>
    sacados.has(c.nombre) ||
    valores[c.nombre] !== comoTexto(detalle.datos[c.nombre])
  const cambios = campos.filter(editado).length
  const listo = vigentes.length > 0 && vigentes.every((c) => !errores[c.nombre])

  function alternar(nombre: string, incluir: boolean) {
    const s = new Set(sacados)
    if (incluir) s.delete(nombre)
    else s.add(nombre)
    setSacados(s)
  }

  return (
    <>
      <form
        id='form-propuesta'
        className='-mx-1 min-h-0 flex-1 space-y-5 overflow-y-auto px-1'
        onSubmit={(e) => {
          e.preventDefault()
          if (listo) aprobar(armarDatos(vigentes, valores, detalle.datos))
        }}
      >
        {detalle.cambio && (
          <p
            role='status'
            className='rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-900 dark:text-amber-200'
          >
            {t('agentes.edit.changed')}
          </p>
        )}
        {campos.map((c) => {
          const fuera = sacados.has(c.nombre)
          const id = `propuesta-${c.nombre}`
          return (
            <div key={c.nombre} className='space-y-1.5'>
              <div className='flex flex-wrap items-center justify-between gap-2'>
                <div className='flex items-center gap-2'>
                  {seSacan && (
                    <Checkbox
                      checked={!fuera}
                      disabled={ocupado}
                      aria-label={t('agentes.edit.include', {
                        field: t(`agentes.field.${c.nombre}`),
                      })}
                      onCheckedChange={(v) => alternar(c.nombre, v === true)}
                    />
                  )}
                  <Label htmlFor={id}>{t(`agentes.field.${c.nombre}`)}</Label>
                  {editado(c) && (
                    <span className='text-xs text-amber-800 dark:text-amber-400'>
                      {t(
                        fuera ? 'agentes.edit.removed' : 'agentes.edit.edited'
                      )}
                    </span>
                  )}
                </div>
                {editado(c) && !fuera && (
                  <Button
                    type='button'
                    variant='ghost'
                    size='sm'
                    className='h-7 px-2 text-xs'
                    onClick={() =>
                      setValores({
                        ...valores,
                        [c.nombre]: comoTexto(detalle.datos[c.nombre]),
                      })
                    }
                  >
                    {t('agentes.edit.restore')}
                  </Button>
                )}
              </div>
              <div
                className={
                  detalle.actual ? 'grid items-start gap-3 sm:grid-cols-2' : ''
                }
              >
                {detalle.actual && (
                  <div className='min-w-0 rounded-md border bg-muted p-2'>
                    <p className='text-xs text-muted-foreground'>
                      {t('agentes.edit.current')}
                    </p>
                    {/* Texto plano: puede haberlo escrito un agente. */}
                    <p className='mt-1 max-h-64 overflow-y-auto text-sm break-words whitespace-pre-wrap'>
                      <Valor campo={c} valor={detalle.actual[c.nombre]} />
                    </p>
                  </div>
                )}
                <Control
                  id={id}
                  campo={c}
                  valor={valores[c.nombre]}
                  inhabilitado={fuera || ocupado}
                  error={errores[c.nombre] ?? null}
                  cambiar={(v) => setValores({ ...valores, [c.nombre]: v })}
                />
              </div>
              {errores[c.nombre] && (
                <p id={`${id}-error`} className='text-xs text-destructive'>
                  {t(`agentes.edit.error_${errores[c.nombre]}`)}
                </p>
              )}
            </div>
          )
        })}
      </form>
      <DialogFooter className='sm:items-center'>
        <p className='mr-auto text-xs text-muted-foreground' role='status'>
          {cambios
            ? t('agentes.edit.count', { count: cambios })
            : t('agentes.edit.no_changes')}
        </p>
        <Button variant='outline' disabled={ocupado} onClick={cerrar}>
          {t('confirm.cancel')}
        </Button>
        <Button
          form='form-propuesta'
          type='submit'
          disabled={!listo || ocupado}
        >
          {t(
            cambios
              ? 'agentes.edit.approve_edited'
              : 'agentes.proposals.approve'
          )}
        </Button>
      </DialogFooter>
    </>
  )
}

function Valor({ campo, valor }: { campo: Campo; valor: unknown }) {
  const { t } = useTranslation()
  const s = comoTexto(valor)
  if (!s)
    return (
      <em className='text-muted-foreground'>
        {t('agentes.proposals.empty_value')}
      </em>
    )
  return campo.opciones
    ? t(`agentes.option.${campo.nombre}.${s}`, { defaultValue: s })
    : s
}

interface PropsControl {
  id: string
  campo: Campo
  valor: string
  inhabilitado: boolean
  error: string | null
  cambiar: (v: string) => void
}

const SIN_VALOR = '-'

function Control({
  id,
  campo,
  valor,
  inhabilitado,
  error,
  cambiar,
}: PropsControl) {
  const { t } = useTranslation()
  const comun = {
    id,
    disabled: inhabilitado,
    'aria-invalid': !!error,
    'aria-describedby': error ? `${id}-error` : undefined,
  }
  if (campo.opciones)
    return (
      <Select
        value={valor || SIN_VALOR}
        disabled={inhabilitado}
        onValueChange={(v) => cambiar(v === SIN_VALOR ? '' : v)}
      >
        <SelectTrigger
          id={id}
          className='w-full'
          aria-invalid={!!error}
          aria-describedby={comun['aria-describedby']}
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {/* Sin valor: en un alta queda el que pone Gungnir por defecto. */}
          {(!valor || VACIABLES.has(campo.nombre)) && (
            <SelectItem value={SIN_VALOR}>{t('agentes.edit.unset')}</SelectItem>
          )}
          {campo.opciones.map((o) => (
            <SelectItem key={o} value={o}>
              {t(`agentes.option.${campo.nombre}.${o}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    )
  if (campo.tipo === 'largo' || campo.tipo === 'lista')
    return (
      <Textarea
        {...comun}
        className='max-h-80 min-h-24'
        value={valor}
        maxLength={campo.max}
        placeholder={
          campo.tipo === 'lista' ? t('agentes.edit.one_per_line') : undefined
        }
        onChange={(e) => cambiar(e.target.value)}
      />
    )
  return (
    <Input
      {...comun}
      value={valor}
      maxLength={campo.max}
      inputMode={campo.tipo === 'numero' ? 'decimal' : undefined}
      onChange={(e) => cambiar(e.target.value)}
    />
  )
}
