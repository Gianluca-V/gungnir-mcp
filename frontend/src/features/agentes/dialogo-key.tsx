import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
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
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  NIVELES_KEY,
  usePermisosAgentes,
  type EngagementAcceso,
  type KeyAgente,
  type Nivel,
} from './comun'

interface Props {
  /** La key a cambiar, o null para una nueva. */
  existente: KeyAgente | null
  cerrar: () => void
}

export function DialogoKey({ existente, cerrar }: Props) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { rol } = usePermisosAgentes()
  const [nombre, setNombre] = useState('')
  const [nivel, setNivel] = useState<Nivel>(
    rol === 'lector' ? 'lectura' : (existente?.nivel_max ?? 'lectura')
  )
  const [dias, setDias] = useState('30')
  const [filtro, setFiltro] = useState('')
  const [elegidos, setElegidos] = useState(
    () => new Set(existente?.engagements.map((e) => e.id) ?? [])
  )
  const [creada, setCreada] = useState<string | null>(null)

  const consulta = useQuery<EngagementAcceso[]>({
    queryKey: ['agentes', 'engagements'],
    queryFn: () => apiFetch<EngagementAcceso[]>('/agentes/engagements'),
  })
  // Los que la key ya tiene se muestran aunque no vengan en la lista: si no, no se podrían quitar.
  const lista = consulta.data ?? []
  const engagements = [
    ...lista,
    ...(existente?.engagements ?? [])
      .filter((e) => !lista.some((x) => x.id === e.id))
      .map((e) => ({ ...e, client_name: '', nivel_max: 'lectura' as Nivel })),
  ]
  const guardar = useMutation({
    mutationFn: () => {
      const comun = { nivel_max: nivel, engagements: [...elegidos] }
      return existente
        ? apiFetch<{ key?: string }>(`/agentes/keys/${existente.id}`, {
            method: 'PATCH',
            body: comun,
          })
        : apiFetch<{ key?: string }>('/agentes/keys', {
            method: 'POST',
            body: { ...comun, nombre: nombre.trim(), dias: Number(dias) },
          })
    },
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['agentes', 'keys'] })
      if (r.key) setCreada(r.key)
      else {
        toast.success(t('agentes.keys.saved'))
        cerrar()
      }
    },
    onError: (e: Error) => toast.error(e.message),
  })

  if (creada) return <KeyCreada valor={creada} cerrar={cerrar} />

  const diasValidos = /^\d{1,3}$/.test(dias) && +dias >= 1 && +dias <= 365
  const visibles = engagements.filter((e) =>
    `${e.title} ${e.client_name}`
      .toLowerCase()
      .includes(filtro.trim().toLowerCase())
  )
  const niveles = rol === 'lector' ? NIVELES_KEY.slice(0, 1) : NIVELES_KEY
  const listo =
    elegidos.size > 0 &&
    consulta.isSuccess &&
    (existente || (nombre.trim() && diasValidos))

  function alternar(id: string, v: boolean) {
    const s = new Set(elegidos)
    if (v) s.add(id)
    else s.delete(id)
    setElegidos(s)
  }

  return (
    <Dialog open onOpenChange={(v) => !v && !guardar.isPending && cerrar()}>
      <DialogContent className='max-h-[90svh] overflow-y-auto sm:max-w-lg'>
        <DialogHeader>
          <DialogTitle>
            {existente
              ? t('agentes.form.title_edit', {
                  name: existente.nombre,
                  interpolation: { escapeValue: false },
                })
              : t('agentes.form.title')}
          </DialogTitle>
          <DialogDescription>{t('agentes.access.intro')}</DialogDescription>
        </DialogHeader>
        <form
          id='form-key'
          className='space-y-5'
          onSubmit={(e) => {
            e.preventDefault()
            if (listo) guardar.mutate()
          }}
        >
          {!existente && (
            <div className='grid grid-cols-[1fr_8rem] gap-3'>
              <div className='space-y-1.5'>
                <Label htmlFor='key-nombre'>{t('agentes.form.name')}</Label>
                <Input
                  id='key-nombre'
                  value={nombre}
                  maxLength={120}
                  placeholder={t('agentes.form.name_ph')}
                  onChange={(e) => setNombre(e.target.value)}
                  autoFocus
                />
              </div>
              <div className='space-y-1.5'>
                <Label htmlFor='key-dias'>{t('agentes.form.days')}</Label>
                <Input
                  id='key-dias'
                  inputMode='numeric'
                  value={dias}
                  aria-invalid={!diasValidos}
                  aria-describedby='key-dias-error'
                  onChange={(e) => setDias(e.target.value)}
                />
              </div>
              {!diasValidos && (
                <p
                  id='key-dias-error'
                  className='col-span-2 text-xs text-destructive'
                >
                  {t('agentes.form.days_error')}
                </p>
              )}
            </div>
          )}

          <fieldset className='space-y-2'>
            <legend className='mb-2 text-sm font-medium'>
              {t('agentes.form.level')}
            </legend>
            <RadioGroup
              value={nivel}
              onValueChange={(v) => setNivel(v as Nivel)}
              className='gap-2'
            >
              {niveles.map((n) => (
                <Label
                  key={n}
                  className='flex cursor-pointer items-start gap-2.5 font-normal'
                >
                  <RadioGroupItem value={n} className='mt-0.5' />
                  <span>
                    <span className='block text-sm font-medium'>
                      {t(`agentes.level.${n}`)}
                    </span>
                    <span className='block text-xs text-muted-foreground'>
                      {t(`agentes.level_desc.${n}`)}
                    </span>
                  </span>
                </Label>
              ))}
            </RadioGroup>
          </fieldset>

          <fieldset className='space-y-2'>
            <legend className='mb-2 text-sm font-medium'>
              {t('agentes.form.engagements')}
            </legend>
            {engagements.length > 6 && (
              <Input
                value={filtro}
                onChange={(e) => setFiltro(e.target.value)}
                placeholder={t('agentes.form.search')}
                aria-label={t('agentes.form.search')}
              />
            )}
            <div className='max-h-48 space-y-1 overflow-y-auto rounded-md border p-2'>
              {visibles.map((e) => (
                <Label
                  key={e.id}
                  className='flex cursor-pointer items-center gap-2.5 rounded px-1 py-1.5 font-normal hover:bg-accent'
                >
                  <Checkbox
                    checked={elegidos.has(e.id)}
                    onCheckedChange={(v) => alternar(e.id, v === true)}
                  />
                  <span className='min-w-0 flex-1 truncate text-sm'>
                    {e.title}
                  </span>
                  {e.nivel_max === 'ninguno' && (
                    <span className='shrink-0 text-xs text-muted-foreground'>
                      {t('agentes.form.no_access')}
                    </span>
                  )}
                </Label>
              ))}
              {consulta.isLoading && (
                <p role='status' className='p-1 text-sm text-muted-foreground'>
                  {t('common.loading')}
                </p>
              )}
              {consulta.isError && (
                <div
                  role='alert'
                  className='flex items-center gap-2 p-1 text-sm'
                >
                  {t('agentes.load_error')}
                  <Button
                    type='button'
                    variant='outline'
                    size='sm'
                    onClick={() => consulta.refetch()}
                  >
                    {t('agentes.retry')}
                  </Button>
                </div>
              )}
              {consulta.isSuccess && !visibles.length && (
                <p className='p-1 text-sm text-muted-foreground'>
                  {t('agentes.form.none_found')}
                </p>
              )}
            </div>
          </fieldset>
        </form>
        <DialogFooter>
          <Button
            variant='outline'
            onClick={cerrar}
            disabled={guardar.isPending}
          >
            {t('common.cancel')}
          </Button>
          <Button
            type='submit'
            form='form-key'
            disabled={!listo || guardar.isPending}
          >
            {guardar.isPending
              ? t('common.loading')
              : existente
                ? t('common.save')
                : t('agentes.form.create')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** La key recién creada. Solo se cierra con el botón, para no perderla por un clic afuera. */
function KeyCreada({ valor, cerrar }: { valor: string; cerrar: () => void }) {
  const { t } = useTranslation()
  const variables = `GUNGNIR_URL=${window.location.origin}\nGUNGNIR_API_KEY=${valor}`
  return (
    <Dialog open>
      <DialogContent
        className='sm:max-w-lg [&>button]:hidden'
        onEscapeKeyDown={(e) => e.preventDefault()}
        onInteractOutside={(e) => e.preventDefault()}
      >
        <DialogHeader>
          <DialogTitle>{t('agentes.created.title')}</DialogTitle>
          <DialogDescription>{t('agentes.created.desc')}</DialogDescription>
        </DialogHeader>
        <div className='min-w-0 space-y-2'>
          <div className='flex items-center justify-between gap-3'>
            <span className='text-sm font-medium'>
              {t('agentes.created.config')}
            </span>
            <BotonCopiar texto={variables} />
          </div>
          <pre className='rounded-md border bg-muted p-3 font-mono text-xs break-all whitespace-pre-wrap select-all'>
            {variables}
          </pre>
        </div>
        <DialogFooter>
          <Button onClick={cerrar}>{t('agentes.created.done')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function BotonCopiar({ texto }: { texto: string }) {
  const { t } = useTranslation()
  const [copiado, setCopiado] = useState(false)
  async function copiar() {
    try {
      // Sin HTTPS el navegador no ofrece el portapapeles.
      await navigator.clipboard.writeText(texto)
      setCopiado(true)
    } catch {
      toast.error(t('agentes.created.copy_error'))
    }
  }
  return (
    <Button variant='outline' size='sm' onClick={copiar}>
      {copiado ? <Check /> : <Copy />}
      {t(copiado ? 'agentes.created.copied' : 'agentes.created.copy')}
    </Button>
  )
}
