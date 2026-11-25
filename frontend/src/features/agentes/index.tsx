/**
 * Agentes: qué puede hacer cada agente conectado por MCP, y lo que espera una decisión humana
 * (propuestas de hallazgos y acciones fuera de alcance).
 */
import { useTranslation } from 'react-i18next'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Accesos } from './accesos'
import { useResumenAgentes } from './comun'
import { Keys } from './keys'
import { Propuestas } from './propuestas'
import { Violaciones } from './violaciones'

export function Agentes() {
  const { t } = useTranslation()
  const { data } = useResumenAgentes()
  return (
    <div className='space-y-6'>
      <div>
        <h1 className='text-xl font-bold'>{t('agentes.title')}</h1>
        <p className='text-sm text-muted-foreground'>{t('agentes.subtitle')}</p>
      </div>
      <Tabs defaultValue='propuestas' className='gap-4'>
        <div className='overflow-x-auto'>
          <TabsList>
            <TabsTrigger value='propuestas'>
              {t('agentes.tab_proposals')}
              <Cuenta n={data?.propuestas} />
            </TabsTrigger>
            <TabsTrigger value='violaciones'>
              {t('agentes.tab_violations')}
              <Cuenta n={data?.violaciones} alerta />
            </TabsTrigger>
            <TabsTrigger value='accesos'>{t('agentes.tab_access')}</TabsTrigger>
            <TabsTrigger value='keys'>{t('agentes.tab_keys')}</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value='propuestas'>
          <Propuestas />
        </TabsContent>
        <TabsContent value='violaciones'>
          <Violaciones />
        </TabsContent>
        <TabsContent value='accesos'>
          <Accesos />
        </TabsContent>
        <TabsContent value='keys'>
          <Keys />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function Cuenta({ n, alerta = false }: { n?: number; alerta?: boolean }) {
  if (!n) return null
  return (
    <span
      className={
        alerta
          ? 'rounded-full bg-red-700 px-1.5 text-xs text-white tabular-nums'
          : 'rounded-full bg-foreground/10 px-1.5 text-xs tabular-nums'
      }
    >
      {n}
    </span>
  )
}
