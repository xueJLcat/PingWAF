import type { Site } from '@/api/types'

export interface IngressDraft {
  listener: string
  agents: string[] | null
  paused: boolean
}

export const defaultIngress: IngressDraft = { listener: '', agents: null, paused: false }

export function siteListener(site: Site | null) {
  return site?.ingress_port && site.ingress_protocol ? `${site.ingress_protocol}:${site.ingress_port}` : ''
}

export function ingressRequest(draft: IngressDraft, original: string, clone = false) {
  const changed = draft.listener !== original
  const [scheme, port] = draft.listener.split(':')
  const fields = changed ? {
    ingress_port: draft.listener ? Number(port) : null,
    ingress_protocol: scheme === 'http' || scheme === 'https' ? scheme : null,
  } as const : {}
  return {
    ...fields,
    ...(draft.listener && !clone && draft.agents !== null ? { ingress_agent_ids: draft.agents } : {}),
    ...(draft.listener && !clone && draft.paused ? { status: 'paused' as const } : {}),
  }
}
