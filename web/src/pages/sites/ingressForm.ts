import type { PortProtocol } from '@/api/sites'
import type { Site } from '@/api/types'

export interface IngressDraft {
  additional?: string[]
  listener: string
  agents: string[] | null
  paused: boolean
}

export const defaultIngress: IngressDraft = { listener: '', agents: null, paused: false }

export function allowsCertificateIssuance(site: Pick<Site, 'ingress_port' | 'ingress_protocol' | 'additional_ingresses'> | null | undefined) {
  if (!site) return false
  const primary = (site.ingress_port == null && site.ingress_protocol == null)
    || (site.ingress_port === 80 && site.ingress_protocol === 'http')
    || (site.ingress_port === 443 && site.ingress_protocol === 'https')
  return primary && (site.additional_ingresses ?? []).every((entry) => entry === 'http:80' || entry === 'https:443')
}

export function siteListener(site: Site | null) {
  return site?.ingress_port && site.ingress_protocol ? `${site.ingress_protocol}:${site.ingress_port}` : ''
}

export function ingressRequest(draft: IngressDraft, original: string, clone = false) {
  const rows = draft.listener ? [draft.listener, ...(draft.additional ?? [])] : []
  // The control-plane primary field identifies the managed socket. Keep the
  // standard pair in the additional set, regardless of its display order.
  const primary = rows.find(row => row !== 'http:80' && row !== 'https:443') ?? draft.listener
  const changed = primary !== original
  const [scheme, port] = primary.split(':')
  const fields = changed ? {
    ingress_port: draft.listener ? Number(port) : null,
    ingress_protocol: scheme === 'http' || scheme === 'https' ? scheme : null,
  } as const : {}
  return {
    ...fields,
    ...(draft.additional ? { additional_ingresses: rows.filter((_, i) => i !== rows.indexOf(primary)) } : {}),
    ...(draft.listener && !clone && draft.agents !== null ? { ingress_agent_ids: draft.agents } : {}),
    ...(draft.listener && !clone && draft.paused ? { status: 'paused' as const } : {}),
  }
}

export function validIngressPort(listener: string, adminPort?: number) {
  if (!listener) return true
  if (!/^(http|https):[1-9]\d{0,4}$/.test(listener)) return false
  const port = Number(listener.split(':')[1])
  return Number.isInteger(port) && port > 0 && port <= 65535 &&
    (port !== 80 || listener === 'http:80') && (port !== 443 || listener === 'https:443') && port !== adminPort
}

export function claimedProtocol(port: string, claims?: PortProtocol[]) {
  return claims?.find(claim => claim.port === Number(port))?.protocol
}

export function ingressPortError(draft: IngressDraft, adminPort?: number, claims?: PortProtocol[], reservedPorts?: number[]) {
  const rows = draft.listener ? [draft.listener, ...(draft.additional ?? [])] : ['http:80', 'https:443']
  if (rows.some(row => reservedPorts?.includes(Number(row.split(':')[1])))) return 'pages.sites.infrastructurePort'
  if (!rows.every(row => validIngressPort(row, adminPort))) return 'pages.sites.ingressPortInvalid'
  if (new Set(rows.map(row => Number(row.split(':')[1]))).size !== rows.length) return 'pages.sites.duplicatePort'
  for (const row of rows) {
    const [scheme, port] = row.split(':')
    const claimed = claimedProtocol(port, claims)
    if (claimed && claimed !== scheme) return 'pages.sites.protocolConflict'
  }
}
