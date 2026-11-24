import { useTranslation } from 'react-i18next'
import type { IngressOptions } from '@/api/sites'
import type { IngressDraft } from './ingressForm'
import { Input } from '@/components/ui/Input'
import { Plus, Trash } from '@phosphor-icons/react'
import { Button } from '@/components/ui/Button'

interface Props {
  value: IngressDraft
  onChange: (value: IngressDraft) => void
  inventory?: IngressOptions
  loadError: boolean
  clone?: boolean
  canPause: boolean
  archive?: boolean
  terminal?: boolean
}

export function SiteIngressFields({ value, onChange, inventory, loadError, clone, canPause, terminal, archive }: Props) {
  const { t } = useTranslation()
  const rows = value.listener ? [value.listener, ...(value.additional ?? [])] : ['http:80', 'https:443']
  const supports = (node: NonNullable<Props['inventory']>['agents'][number]) => (!terminal || node.supports_site_handlers) && (!archive || node.supports_site_archives)
  const candidates = (rows: string[]) => (inventory?.agents ?? []).filter(agent => supports(agent) && rows.every(listener => {
    const [scheme, port] = listener.split(':')
    const bound = agent.listeners.find(([number]) => number === Number(port))
    return bound ? bound[1] === scheme : agent.dynamic_bind
  }))
  const selected = value.agents ?? inventory?.assigned_agent_ids ?? []
  const eligible = candidates(rows)
  function changeRows(next: string[]) {
    const usual = !terminal && next.length === 2 && next.includes('http:80') && next.includes('https:443')
    const agents = candidates(next)
    onChange({ ...value, listener: usual ? '' : next[0], additional: usual ? [] : next.slice(1),
      agents: !usual && value.agents === null && !selected.length && agents.length === 1
        ? [agents[0].id] : selected })
  }
  const unavailable = selected.filter(id => !eligible.some(agent => agent.id === id))
  const toggle = (id: string) => onChange({
    ...value, agents: selected.includes(id) ? selected.filter(item => item !== id) : [...selected, id],
  })

  return <div className="space-y-2">
    {rows.map((row, index) => {
      const [scheme, port] = row.split(':')
      const edit = (entry: string) => changeRows(rows.map((old, i) => i === index ? entry : old))
      return <div key={index} className="flex items-end gap-2">
        <div className="min-w-0 flex-1"><Input label={t('pages.sites.ingressPort')} type="number" min={1} max={65535} value={port}
          disabled={!inventory?.writes_enabled} onChange={event => edit(`${scheme}:${event.target.value}`)} required /></div>
        <div className="flex rounded-md border border-border p-1" role="group" aria-label={t('pages.sites.ingressLabel')}>
          {['http', 'https'].map(protocol => <button type="button" key={protocol} aria-pressed={scheme === protocol}
            disabled={!inventory?.writes_enabled} className={`rounded px-2 py-1 text-xs ${scheme === protocol ? 'bg-brand text-white' : 'text-fg-subtle'}`}
            onClick={() => edit(`${protocol}:${port}`)}>{protocol.toUpperCase()}</button>)}
        </div>
        <Button variant="ghost" disabled={rows.length === 1 || !inventory?.writes_enabled}
          aria-label={t('common.delete')} onClick={() => changeRows(rows.filter((_, i) => i !== index))}><Trash /></Button>
      </div>
    })}
    <Button variant="ghost" className="w-full border border-border" icon={<Plus />} disabled={!inventory?.writes_enabled || rows.length >= 32}
      onClick={() => changeRows([...rows, 'http:'])}>{t('pages.sites.ingressAddPort')}</Button>
    {loadError && <p role="alert">{t('pages.sites.ingressLoadError')}</p>}
    {value.listener.startsWith('http:') && <p className="text-xs text-fg-subtle">{t('pages.sites.ingressHsts')}</p>}
    {value.listener && !clone && <fieldset className="space-y-1.5 text-sm">
      <legend className="mb-1 text-fg-subtle">{t('pages.sites.ingressAgents')}</legend>
      {terminal && inventory?.agents.filter(agent => !supports(agent)).map(agent =>
        <p key={agent.id} className="text-xs text-fg-subtle">{agent.name} · {t('pages.sites.handlerUpgrade')}</p>)}
      {eligible.map(agent => <label key={agent.id} className="flex items-center gap-2">
        <input type="checkbox" checked={selected.includes(agent.id)} onChange={() => toggle(agent.id)} />{agent.name}
      </label>)}
      {unavailable.map(id => <label key={id} className="flex items-center gap-2">
        <input type="checkbox" checked onChange={() => toggle(id)} />{inventory?.agents.find(node => node.id === id)?.name ?? id} · {t('pages.sites.ingressUnavailable')}
      </label>)}
      {canPause && <label className="flex items-center gap-2">
        <input type="checkbox" checked={value.paused} onChange={event => onChange({ ...value, paused: event.target.checked })} />
        {t('pages.sites.ingressStage')}
      </label>}
    </fieldset>}
  </div>
}
