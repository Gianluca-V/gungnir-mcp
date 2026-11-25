import { describe, expect, it } from 'vitest'
import { armarDatos, CAMPOS, comoTexto, errorDe } from './campos'

const campo = (n: string) => CAMPOS.find((c) => c.nombre === n)!
const elegidos = (...n: string[]) => n.map(campo)

describe('armarDatos', () => {
  it('lo que no se tocó va igual a como lo propuso el agente', () => {
    const p = {
      title: 'T',
      cvss_score_31: 8.1,
      references_list: ['a', 'b'],
      cwe_id: null,
    }
    const cs = elegidos('title', 'cvss_score_31', 'references_list', 'cwe_id')
    const v = Object.fromEntries(
      cs.map((c) => [c.nombre, comoTexto(p[c.nombre as keyof typeof p])])
    )
    expect(armarDatos(cs, v, p)).toEqual(p)
  })
  it('convierte números con coma y listas por línea', () => {
    expect(
      armarDatos(
        elegidos('cvss_score_31', 'references_list'),
        { cvss_score_31: '7,5', references_list: ' a \n\n b ' },
        {}
      )
    ).toEqual({ cvss_score_31: 7.5, references_list: ['a', 'b'] })
  })
  it('vaciar borra el dato propuesto y lo que nunca estuvo no se manda', () => {
    expect(
      armarDatos(
        elegidos('description', 'references_list', 'phase_type', 'cwe_id'),
        { description: '', references_list: '', phase_type: '', cwe_id: '' },
        { description: 'x', references_list: ['x'], phase_type: 'recon' }
      )
    ).toEqual({ description: null, references_list: [], phase_type: null })
  })
  it('solo manda los campos que se aplican', () => {
    expect(
      armarDatos(
        elegidos('severity'),
        { severity: 'low', title: 'otro' },
        { severity: 'high', title: 'T' }
      )
    ).toEqual({ severity: 'low' })
  })
})

describe('errorDe', () => {
  it('exige título y activo, y admite vacío en el resto', () => {
    expect(errorDe(campo('title'), '  ')).toBe('required')
    expect(errorDe(campo('affected_asset'), '')).toBe('required')
    expect(errorDe(campo('description'), '')).toBeNull()
  })
  it.each(['0', '10', '7,5', '7.5'])('puntaje %s es válido', (v) =>
    expect(errorDe(campo('cvss_score_31'), v)).toBeNull()
  )
  it.each(['11', '-1', 'x', '7.5.1'])('puntaje %s no es válido', (v) =>
    expect(errorDe(campo('cvss_score_31'), v)).toBe('score')
  )
  it('limita las referencias', () => {
    expect(errorDe(campo('references_list'), 'x\n'.repeat(51))).toBe('list')
    expect(errorDe(campo('references_list'), 'x'.repeat(1001))).toBe('list')
  })
})
