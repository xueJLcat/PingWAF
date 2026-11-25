import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/api/client'
import { Badge, Button, Dialog, Input } from '@/components/ui'

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
  function startEdit() {
    if (!data) return
    write.reset()
    setDraft({
      revision: data.policy.revision,
      base: data.policy.addresses?.join(', ') ?? '',
      sites: data.sites,
      overrides: Object.fromEntries(data.policy.overrides.map(o => [key(o), o.addresses.join(', ')])),
    })
  }
  const footer = draft ? <>
    <Button disabled={write.isPending} onClick={() => setDraft(undefined)}>{t('common.cancel')}</Button>
    <Button form="listener-policy-form" type="submit" variant="primary" loading={write.isPending}
      disabled={!addresses(draft.base).length}>{t('common.save')}</Button>
  </> : <Button disabled={!data || (data.online && !observed)} onClick={startEdit}>{t('common.edit')}</Button>
  return <Dialog open title={label('title')} description={name ?? node} size="lg" footer={footer}
    onClose={() => { if (!write.isPending) close() }}>
    {query.isPending && <p role="status">{t('common.loading')}</p>}
    {query.error && <p role="alert" className="text-sm text-fg-danger">{query.error.message}</p>}
    {data && <div className="min-w-0 space-y-5 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge dot tone={state === 'applied' ? 'success' : state === 'partial' ? 'danger' : 'neutral'}>{label(state)}</Badge>
        <span className="text-fg-subtle" title={data.policy.updated_by}>{label('revision', {revision: data.policy.revision})}</span>
      </div>
      {draft ? <form id="listener-policy-form" className="space-y-4" onSubmit={e => {
        e.preventDefault()
        if (!write.isPending && addresses(draft.base).length) write.mutate()
      }}>
        <Input label={label('base')} hint={label('hint')} required value={draft.base} disabled={write.isPending}
          onChange={e => setDraft({ ...draft, base: e.target.value })} />
        {draft.sites.length > 0 && <fieldset className="space-y-3">
          <legend className="mb-2 font-medium">{label('overrides')}</legend>
          {draft.sites.map(site => <Input key={key(site)} label={site.domain + ' · ' + site.port} placeholder={label('inherit')}
            disabled={write.isPending} value={draft.overrides[key(site)] ?? ''}
            onChange={e => setDraft({ ...draft, overrides: { ...draft.overrides, [key(site)]: e.target.value } })} />)}
        </fieldset>}
        {write.error && <p role="alert" className="text-fg-danger">{write.error.message}</p>}
      </form> : <>
        <section>
          <h3 className="mb-2 font-medium">{label('base')}</h3>
          <p className="break-all rounded-md border border-line bg-recessed px-3 py-2 font-mono">{data.policy.addresses?.join(', ') ?? label('review')}</p>
        </section>
        {data.sites.length > 0 && <section>
          <h3 className="mb-2 font-medium">{label('overrides')}</h3>
          <ul className="divide-y divide-line rounded-md border border-line">
            {data.sites.map(site => <li key={key(site)} className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 px-3 py-2">
              <span className="min-w-0 break-all">{site.domain}<span className="font-mono text-fg-subtle">:{site.port}</span></span>
              <span className="break-all text-fg-subtle">{data.policy.overrides.find(o => key(o) === key(site))?.addresses.join(', ') ?? label('inherit')}</span>
            </li>)}
          </ul>
        </section>}
      </>}
      {observed && <section className="border-t border-line pt-4">
        <h3 className="font-medium">{label('report')}</h3>
        <p className="mb-2 mt-1 text-xs text-fg-subtle">{label('generation', { desired: observed.desired_generation, applied: observed.applied_generation || label('pending') })}</p>
        {observed.sockets.length === 0 && <p className="text-fg-subtle">{label('empty')}</p>}
        <ul className="divide-y divide-line">
          {observed.sockets.map(s => <li key={s.protocol + '/' + s.address + '/' + s.port} className="flex flex-wrap items-center justify-between gap-2 py-2">
            <span className="flex min-w-0 items-center gap-2"><Badge>{s.protocol.toUpperCase()}</Badge>
              <code className="break-all">{s.address.includes(':') ? '[' + s.address + ']' : s.address}:{s.port}</code></span>
            <Badge tone={s.bound ? 'success' : 'danger'}>{s.bound ? label('bound') : (s.error || label('partial'))}</Badge>
          </li>)}
        </ul>
      </section>}
    </div>}
  </Dialog>
}
