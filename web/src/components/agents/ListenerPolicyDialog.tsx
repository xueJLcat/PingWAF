import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { Button, Dialog, Input } from '@/components/ui'

interface SiteEndpoint { site_id: string; domain: string; port: number }
interface Override { site_id: string; port: number; addresses: string[] }
interface Policy { revision: number; addresses: string[] | null; overrides: Override[]; updated_by: string }
interface Inventory {
  policy: Policy
  sites: SiteEndpoint[]
  online: boolean
  observed: {
    desired_generation: number; applied_generation: number; policy_revision: number
    sockets: { address: string; port: number; protocol: string; bound: boolean; error: string }[]
  } | null
}

const addresses = (raw: string) => raw.split(/[\s,，]+/).filter(Boolean)
const key = (site: Pick<SiteEndpoint, 'site_id' | 'port'>) => site.site_id + '/' + site.port

export function ListenerPolicyDialog({ node, name, close }: { node: string; name?: string; close: () => void }) {
  const { t } = useTranslation()
  const { t: label } = useTranslation('common', { keyPrefix: 'pages.agents.listenerPolicy' })
  const client = useQueryClient()
  const url = '/agents/' + encodeURIComponent(node) + '/listener-policy'
  const queryKey = ['node-listener-policy', node]
  const query = useQuery({ queryKey, queryFn: () => apiClient.get<Inventory>(url), refetchInterval: 5000 })
  const data = query.data
  const [draft, setDraft] = useState<{ revision: number; base: string; sites: SiteEndpoint[]; overrides: Record<string, string> }>()
  const write = useMutation({
    mutationFn: async () => {
      if (!draft) return
      const overrides = draft.sites.flatMap(site => {
        const ips = addresses(draft.overrides[key(site)] ?? '')
        return ips.length ? [{ site_id: site.site_id, port: site.port, addresses: ips }] : []
      })
      await apiClient.put(url, { revision: draft.revision, addresses: addresses(draft.base), overrides })
    },
    onSuccess: async () => {
      setDraft(undefined)
      await Promise.all([query.refetch(), client.invalidateQueries({ predicate: query => query.queryKey.includes('ingress-options') })])
    },
  })
  const observed = data?.observed
  const state = !data?.online ? 'offline' : !observed ? 'incompatible'
    : observed.sockets.some(s => !s.bound) ? 'partial'
    : observed.policy_revision !== data.policy.revision || !observed.applied_generation || observed.applied_generation !== observed.desired_generation ? 'pending' : 'applied'
  return <Dialog open title={label('title')} description={name ?? node} size="lg" onClose={() => { if (!write.isPending) close() }}>
    {query.isPending && <p role="status">{t('common.loading')}</p>}
    {query.error && <p role="alert">{query.error.message}</p>}
    {data && <div className="space-y-4">
      <p>{label('revision', { revision: data.policy.revision })} · {label(state)}{data.policy.updated_by && ' · ' + data.policy.updated_by}</p>
      {draft ? <form className="space-y-3" onSubmit={e => { e.preventDefault(); write.mutate() }}>
        <Input label={label('base')} hint={label('hint')} required value={draft.base}
          onChange={e => setDraft({ ...draft, base: e.target.value })} />
        {draft.sites.map(site => <Input key={key(site)} label={site.domain + ' · ' + site.port} placeholder={label('inherit')}
          value={draft.overrides[key(site)] ?? ''} onChange={e => setDraft({ ...draft, overrides: { ...draft.overrides, [key(site)]: e.target.value } })} />)}
        {write.error && <p role="alert" className="text-fg-danger">{write.error.message}</p>}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" disabled={write.isPending} onClick={() => setDraft(undefined)}>{t('common.cancel')}</Button>
          <Button type="submit" disabled={write.isPending || !addresses(draft.base).length}>{t('common.save')}</Button>
        </div>
      </form> : <>
        <p>{label('base')} · {data.policy.addresses?.join(', ') ?? label('review')}</p>
        <ul>{data.sites.map(site => <li key={key(site)}>{site.domain} · {site.port} · {data.policy.overrides.find(o => key(o) === key(site))?.addresses.join(', ') ?? label('inherit')}</li>)}</ul>
        <Button variant="secondary" disabled={data.online && !observed} onClick={() => {
          write.reset()
          setDraft({ revision: data.policy.revision, base: data.policy.addresses?.join(', ') ?? '', sites: data.sites,
            overrides: Object.fromEntries(data.policy.overrides.map(o => [key(o), o.addresses.join(', ')])) })
        }}>{t('common.edit')}</Button>
      </>}
      {observed && <section className="space-y-1">
        <h3>{label('report')}</h3>
        <p>{label('generation', { desired: observed.desired_generation, applied: observed.applied_generation || label('pending') })}</p>
        {observed.sockets.length === 0 && <p>{label('empty')}</p>}
        {observed.sockets.map(s => <p key={s.address + '/' + s.port}>{s.protocol.toUpperCase()} {s.address.includes(':') ? '[' + s.address + ']' : s.address}:{s.port} · {s.bound ? label('bound') : s.error}</p>)}
      </section>}
    </div>}
  </Dialog>
}
