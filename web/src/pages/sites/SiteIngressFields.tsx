import { useTranslation } from 'react-i18next'
import type { IngressOptions } from '@/api/sites'
import type { IngressDraft } from './ingressForm'
import { Select } from '@/components/ui/Select'

interface Props {
  value: IngressDraft
  onChange: (value: IngressDraft) => void
  inventory?: IngressOptions
  loadError: boolean
  clone?: boolean
  canPause: boolean
}

export function SiteIngressFields({ value, onChange, inventory, loadError, clone, canPause }: Props) {
  const { t } = useTranslation()
  const options = new Map<string, number>()
  for (const agent of inventory?.agents ?? []) {
    for (const [port, protocol] of agent.listeners) options.set(`${protocol}:${port}`, port)
  }
  const selected = value.agents ?? inventory?.assigned_agent_ids ?? []
  const eligible = (inventory?.agents ?? []).filter(agent =>
    agent.listeners.some(([port, protocol]) => `${protocol}:${port}` === value.listener))
  const unavailable = selected.filter(id => !eligible.some(agent => agent.id === id))
  const toggle = (id: string) => onChange({
    ...value, agents: selected.includes(id) ? selected.filter(item => item !== id) : [...selected, id],
  })

  return <div className="space-y-2">
    <Select label={t('pages.sites.ingressLabel')} value={value.listener}
      onChange={event => onChange({ listener: event.target.value, agents: [], paused: false })}
      hint={loadError ? t('pages.sites.ingressLoadError') : inventory && !inventory.writes_enabled ? t('pages.sites.ingressGated') : undefined}>
      <option value="">{t('pages.sites.ingressDefault')}</option>
      {value.listener && !options.has(value.listener) && <option value={value.listener}>{value.listener.toUpperCase()}</option>}
      {[...options].sort(([a, pa], [b, pb]) => pa - pb || a.localeCompare(b)).map(([key]) =>
        <option key={key} value={key} disabled={!inventory?.writes_enabled}>{key.toUpperCase()}</option>)}
    </Select>
    {value.listener.startsWith('http:') && <p className="text-xs text-fg-subtle">{t('pages.sites.ingressHsts')}</p>}
    {value.listener && !clone && <fieldset className="space-y-1.5 text-sm">
      <legend className="mb-1 text-fg-subtle">{t('pages.sites.ingressAgents')}</legend>
      {eligible.map(agent => <label key={agent.id} className="flex items-center gap-2">
        <input type="checkbox" checked={selected.includes(agent.id)} onChange={() => toggle(agent.id)} />{agent.name}
      </label>)}
      {unavailable.map(id => <label key={id} className="flex items-center gap-2">
        <input type="checkbox" checked onChange={() => toggle(id)} />{id} · {t('pages.sites.ingressUnavailable')}
      </label>)}
      {canPause && <label className="flex items-center gap-2">
        <input type="checkbox" checked={value.paused} onChange={event => onChange({ ...value, paused: event.target.checked })} />
        {t('pages.sites.ingressStage')}
      </label>}
    </fieldset>}
  </div>
}
