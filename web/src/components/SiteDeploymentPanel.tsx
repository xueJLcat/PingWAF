import { useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { ArrowClockwise, PaperPlaneTilt } from '@phosphor-icons/react'
import { agentsApi, agentKeys } from '@/api/agents'
import { errorMessage } from '@/api/errors'
import { sitesApi, siteKeys, type SiteDeployment } from '@/api/sites'
import { useCanWrite } from '@/hooks'
import { formatDateTime } from '@/lib/format'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { useToast } from './ui/Toast'
import { ErrorState } from './ErrorState'

const prefix = 'pages.siteDetail.deployment.'
type DeploymentNode = SiteDeployment['nodes'][number]

function NodeCard({ node, desired, refresh }: {
  node: DeploymentNode
  desired: string | null
  refresh: () => Promise<void>
}) {
  const { t } = useTranslation()
  const canWrite = useCanWrite()
  const toast = useToast()
  const sending = useRef(false)
  const command = useMutation({
    mutationFn: () => agentsApi.sendCommand(node.id, { command: 'reload' }),
    onSuccess: () => toast.success(t(prefix + 'push'), t('pages.agents.manual_pending')),
    onSettled: refresh,
  })
  const send = async () => {
    if (sending.current || !node.connected || !canWrite) return
    sending.current = true
    try {
      await command.mutateAsync()
    } catch {
      // The inline error remains visible next to this node's retry button.
    } finally {
      sending.current = false
    }
  }
  const applied = node.entries.filter(entry => entry.state === 'applied').length
  return <article className="min-w-0 overflow-hidden rounded-lg border border-line bg-elevated">
    <header className="flex flex-wrap items-start justify-between gap-3 bg-recessed/60 px-4 py-3">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="break-all font-semibold">{node.name}</h3>
          <Badge dot tone={node.connected ? 'success' : 'neutral'}>{t(node.connected ? 'status.online' : 'status.offline')}</Badge>
        </div>
        <div className="text-xs text-fg-subtle">{t(node.scope === 'all' ? 'pages.agents.siteScopeAll' : 'pages.agents.siteScopeSelected')} · {applied}/{node.entries.length}</div>
      </div>
      {canWrite && <div className="max-w-sm sm:text-right">
        <Button size="sm" disabled={!node.connected} loading={command.isPending} onClick={() => void send()}
          icon={<PaperPlaneTilt className="h-4 w-4" />}>{t(prefix + 'push')}</Button>
        <p className="mt-1 text-xs text-fg-subtle">{t(node.connected ? prefix + 'pushHint' : 'pages.agents.manual_offline')}</p>
      </div>}
    </header>
    {command.isError && <div role="alert" className="px-4 pt-2 text-sm text-fg-danger">{errorMessage(command.error)}</div>}
    {node.manual_sync && <p role="status" className="px-4 pt-2 text-xs text-fg-subtle">
      {t(prefix + 'lastPush')} · {t('pages.agents.manual_' + node.manual_sync.status)} · <time dateTime={node.manual_sync.requested_at}>{formatDateTime(node.manual_sync.requested_at)}</time>
    </p>}
    <ul className="divide-y divide-line">
      {node.entries.map(entry => <li key={entry.protocol + entry.port} className="space-y-2 px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <code className="font-semibold">{entry.protocol.toUpperCase()} {entry.port}</code>
          <Badge tone={entry.state === 'applied' ? 'success' : entry.state === 'failed' ? 'danger' : 'neutral'}>{t(prefix + entry.state)}</Badge>
          {entry.failure_code && <span className="text-sm text-fg-danger">{t(prefix + entry.failure_code)}</span>}
        </div>
        <dl className="grid gap-2 text-xs sm:grid-cols-3">
          <div><dt className="text-fg-subtle">{t(prefix + 'listener')}</dt><dd>{t(prefix + (entry.bound === null ? 'bindUnknown' : entry.bound ? 'bound' : 'unbound'))}</dd></div>
          <div><dt className="text-fg-subtle">{t(prefix + 'observed')}</dt><dd>{entry.observed_at ? <time dateTime={entry.observed_at}>{formatDateTime(entry.observed_at)}</time> : t(prefix + 'noReceipt')}</dd></div>
          <div><dt className="text-fg-subtle">{t(prefix + 'appliedRevision')}</dt><dd><code>{entry.applied_revision?.slice(0, 12) ?? '—'}</code></dd></div>
        </dl>
        {(desired || entry.applied_revision) && <details className="text-xs">
          <summary className="cursor-pointer text-link">{t(prefix + 'revisionDetails')}</summary>
          <dl className="mt-2 space-y-2 rounded-md bg-recessed p-2">
            {[[t(prefix + 'desired'), desired], [t(prefix + 'appliedRevision'), entry.applied_revision]].map(([label, value]) =>
              <div key={label}><dt className="text-fg-subtle">{label}</dt><dd className="break-all font-mono select-all">{value ?? '—'}</dd></div>)}
          </dl>
        </details>}
      </li>)}
    </ul>
  </article>
}

export function SiteDeploymentPanel({ siteId }: { siteId: string }) {
  const { t } = useTranslation()
  const client = useQueryClient()
  const deployment = useQuery({
    queryKey: [...siteKeys.all, siteId, 'deployment'],
    queryFn: () => sitesApi.deployment(siteId),
    refetchInterval: query => query.state.data?.nodes.some(node => node.manual_sync?.status === 'pending') ? 3000 : 20000,
  })
  const refresh = async () => {
    await Promise.all([
      deployment.refetch(),
      client.invalidateQueries({ queryKey: [...siteKeys.all, 'deployment-summaries'] }),
      client.invalidateQueries({ queryKey: agentKeys.all }),
    ])
  }
  const data = deployment.data
  return <section className="mb-4 space-y-3 rounded-lg border border-line p-3 text-sm sm:p-4" aria-label={t(prefix + 'title')}>
    <header className="flex flex-wrap items-center justify-between gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="font-semibold">{t(prefix + 'title')}</h2>
        {data && data.nodes.length > 0 && <Badge tone={data.summary.failed ? 'danger' : data.summary.applied === data.summary.total ? 'success' : 'neutral'}>
          {t(prefix + 'count', { ...data.summary })}
        </Badge>}
      </div>
      <Button size="sm" loading={deployment.isFetching} onClick={() => void deployment.refetch()} icon={<ArrowClockwise className="h-4 w-4" />}>{t('common.refresh')}</Button>
    </header>
    {deployment.isError ? <ErrorState variant="inline" error={deployment.error} /> : deployment.isPending ? <p role="status">{t('common.loading')}</p>
      : data.nodes.length ? data.nodes.map(node => <NodeCard key={node.id} node={node} desired={data.desired_revision} refresh={refresh} />)
      : <p className="text-fg-subtle">{t(prefix + 'empty')}</p>}
  </section>
}
