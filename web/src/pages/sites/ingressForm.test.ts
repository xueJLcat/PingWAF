import { describe, expect, it } from 'vitest'
import { defaultIngress, ingressPortError, ingressRequest } from './ingressForm'

describe('ingress form payload', () => {
  it('checks infrastructure ports for primary, additional and implicit listeners', () => {
    const check = (listener: string, additional: string[] = [], reserved = [5432, 9091]) =>
      ingressPortError({ ...defaultIngress, listener, additional }, 9080, [], reserved)
    expect(check('https:5432')).toBe('pages.sites.infrastructurePort')
    expect(check('http:81', ['http:9091'])).toBe('pages.sites.infrastructurePort')
    expect(check('', [], [80])).toBe('pages.sites.infrastructurePort')
    expect(check('other:81')).toBe('pages.sites.ingressPortInvalid')
    expect(check('http:81:82')).toBe('pages.sites.ingressPortInvalid')
    expect(check('http:81')).toBeUndefined()
  })

  it('checks primary and additional ports against other sites while allowing HTTP sharing', () => {
    const claims = [{ port: 8080, protocol: 'http' as const }]
    const draft = { ...defaultIngress, listener: 'http:8080' }
    expect(ingressPortError(draft, 9080, claims)).toBeUndefined()
    expect(ingressPortError({ ...draft, listener: 'https:8080' }, 9080, claims)).toBe('pages.sites.protocolConflict')
    expect(ingressPortError({ ...draft, listener: 'http:81', additional: ['https:8080'] }, 9080, claims)).toBe('pages.sites.protocolConflict')
    expect(ingressPortError({ ...draft, additional: ['https:8080'] }, 9080, claims)).toBe('pages.sites.duplicatePort')
  })

  it('preserves an unchanged listener and assignments when editing', () => {
    expect(ingressRequest({ ...defaultIngress, listener: 'https:82' }, 'https:82')).toEqual({})
  })

  it('explicitly clears both fields when returning to default', () => {
    expect(ingressRequest(defaultIngress, 'http:81')).toEqual({ ingress_port: null, ingress_protocol: null })
  })

  it('sends the selected agents and permits staging with none', () => {
    expect(ingressRequest({ listener: 'http:81', agents: ['a'], paused: false }, '')).toEqual({
      ingress_port: 81, ingress_protocol: 'http', ingress_agent_ids: ['a'],
    })
    expect(ingressRequest({ listener: 'https:82', agents: [], paused: true }, 'https:82')).toEqual({
      ingress_agent_ids: [], status: 'paused',
    })
  })

  it('changes the clone listener without sending source assignments', () => {
    expect(ingressRequest({ listener: 'http:81', agents: ['a'], paused: true }, 'https:82', true)).toEqual({
      ingress_port: 81, ingress_protocol: 'http',
    })
  })
})
