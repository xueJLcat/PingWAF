import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowClockwise } from '@phosphor-icons/react'
import { agentsApi, agentKeys } from '@/api/agents'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { ErrorState } from '@/components/ErrorState'

const prefix = 'pages.siteDetail.deployment.'

export function NodeSiteEntries({ id }: { id: string }) {
  const { t } = useTranslation()
  const [page, setPage] = useState(1)
  const query = useQuery({
    queryKey: [...agentKeys.detail(id), 'site-entries', page],
    queryFn: () => agentsApi.siteEntries(id, page),
    refetchInterval: 20000,
  })
  const data = query.data
  const title = t(prefix + 'nodeEntries')
  return <section aria-label={title} className="min-w-0 rounded-lg border border-line">
    <header className="flex items-center justify-between gap-2 px-3 py-2">
      <h3 className="font-semibold">{title}</h3>
      <Button size="sm" variant="ghost" loading={query.isFetching} aria-label={t('common.refresh') + ' · ' + title}
        onClick={() => void query.refetch()} icon={<ArrowClockwise className="h-4 w-4" />}>{t('common.refresh')}</Button>
    </header>
    {query.isError ? <ErrorState variant="inline" error={query.error} onRetry={() => void query.refetch()} />
      : !data ? <p role="status" className="px-3 pb-3 text-sm">{t('common.loading')}</p>
      : data.total === 0 ? <p className="px-3 pb-3 text-sm text-fg-subtle">{t(prefix + 'noAssignedSites')}</p>
      : <>
        <div className="max-h-80 overflow-auto" tabIndex={0} role="region" aria-label={title + ' · ' + t('common.details')}>
          <table className="w-full whitespace-nowrap text-left text-sm" aria-label={title}>
            <thead className="sticky top-0 z-10 bg-recessed text-xs text-fg-subtle"><tr>
              {[t('pages.agents.site'), t(prefix + 'entry'), t('common.status'), t(prefix + 'failureReason')].map(label =>
                <th scope="col" key={label} className="px-3 py-2 font-medium">{label}</th>)}
            </tr></thead>
            <tbody>{data.items.flatMap(site => site.entries.map(entry =>
              <tr key={site.id + ':' + entry.protocol + ':' + entry.port} className="border-t border-line hover:bg-recessed/60">
                <td className="px-3 py-2"><Link to={`/sites/${site.id}/basic`} title={site.domain}
                  className="block max-w-48 truncate font-medium text-link hover:underline">{site.domain}</Link></td>
                <td className="px-3 py-2 font-mono tabular-nums">{entry.protocol.toUpperCase()} {entry.port}</td>
                <td className="px-3 py-2"><Badge dot size="sm" tone={entry.state === 'failed' ? 'danger' : entry.state === 'applied' ? 'success' : 'neutral'}>
                  {site.status === 'paused' && t('status.paused') + ' · '}{t(prefix + entry.state)}
                </Badge></td>
                <td className={entry.failure_code ? 'px-3 py-2 text-fg-danger' : 'px-3 py-2 text-fg-subtle'}>{entry.failure_code ? t(prefix + entry.failure_code) : '—'}</td>
              </tr>))}</tbody>
          </table>
        </div>
        {data.total > data.page_size && <nav aria-label={t('pagination.label')} className="flex items-center justify-end gap-2 border-t border-line px-3 py-1.5 text-xs">
          <Button size="sm" disabled={data.page <= 1} onClick={() => setPage(data.page - 1)}>{t('pagination.previous')}</Button>
          <span>{data.page} / {Math.ceil(data.total / data.page_size)}</span>
          <Button size="sm" disabled={data.page * data.page_size >= data.total} onClick={() => setPage(data.page + 1)}>{t('pagination.next')}</Button>
        </nav>}
      </>}
  </section>
}
