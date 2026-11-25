import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { agentsApi } from '@/api/agents'
import { sitesApi } from '@/api/sites'
import { ErrorState } from '@/components/ErrorState'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Pagination } from '@/components/ui/Pagination'
import { useDebouncedValue } from '@/hooks'
import { formatSiteAddress } from '@/lib/format'
import { useAuthStore } from '@/stores/authStore'

export function MaintenanceTargetsPage({ target }: { target: 'sites' | 'agents' }) {
  const { t } = useTranslation()
  const user = useAuthStore(s => s.user?.id)
  const canWrite = useAuthStore(s => s.user?.role === 'admin')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const query = { search: useDebouncedValue(search.trim()), page, page_size: 20 }
  const list = useQuery({
    queryKey: ['maintenance-targets', user, target, query],
    queryFn: async () => {
      if (target === 'agents') {
        const result = await agentsApi.list(query)
        return { total: result.total, rows: result.items.map(node => ({
          id: node.id, name: node.display_name || node.hostname, detail: node.hostname,
          to: '/agents?directories=' + encodeURIComponent(node.id),
        })) }
      }
      const result = await sitesApi.list(query)
      return { total: result.total, rows: result.items.map(site => ({
        id: site.id, name: formatSiteAddress(site), detail: site.name,
        to: site.ingress_port && site.site_handler?.kind !== 'redirect'
          ? `/sites/${site.id}/security/protection?tab=integrity` : '',
      })) }
    },
  })
  return <div className="animate-slide-up">
    <PageHeader title={t(target === 'sites' ? 'pages.sites.pageProtection' : 'nav.staticDirectories')}
      description={t(target === 'sites' ? 'nav.chooseProtectionSite' : 'nav.chooseDirectoryNode')} />
    <Card><CardBody className="space-y-3">
      <Input type="search" label={t('common.search')} value={search} onChange={e => { setSearch(e.target.value); setPage(1) }} />
      {list.isPending && <p role="status">{t('common.loading')}</p>}
      {list.isError && <ErrorState variant="inline" error={list.error} onRetry={() => void list.refetch()} />}
      {list.data && <>
        {!list.data.rows.length && <div className="space-y-2 text-sm">
          <p role="status" className="text-fg-subtle">{t('nav.noTargets')}</p>
          {!search && canWrite && <Link className="text-fg-brand-strong underline" to={target === 'sites' ? '/sites?new=1' : '/agents'}>
            {t(target === 'sites' ? 'pages.sites.addSite' : 'nav.agents')}
          </Link>}
        </div>}
        <ul className="divide-y divide-line">{list.data.rows.map(row =>
          <li key={row.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
            {row.to ? <Link className="min-w-0 break-all py-2 font-medium text-fg-brand-strong underline" to={row.to}>{row.name}</Link> : <span className="break-all">{row.name}</span>}
            {!row.to && <span className="text-fg-subtle">{t('nav.protectionUnavailable')}</span>}
            {row.to && row.detail !== row.name && <span className="break-all text-fg-subtle">{row.detail}</span>}
          </li>)}</ul>
        {(page > 1 || list.data.total > query.page_size) && <Pagination page={page} pageSize={query.page_size} total={list.data.total} onChange={setPage} />}
      </>}
    </CardBody></Card>
  </div>
}
