import { describe, expect, it } from 'vitest'
import { defaultIngress, ingressRequest } from './ingressForm'

describe('ingress form payload', () => {
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
