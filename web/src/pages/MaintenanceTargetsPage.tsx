import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { agentsApi } from '@/api/agents'
import { sitesApi } from '@/api/sites'
import { ErrorState } from '@/components/ErrorState'
import { PageHeader } from '@/components/PageHeader'
import { Card, CardBody } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/EmptyState'
import { StaticRootsDialog } from '@/components/agents/StaticRootsDialog'
import { Desktop, Globe, MagnifyingGlass } from '@phosphor-icons/react'
import { Pagination } from '@/components/ui/Pagination'
import { useDebouncedValue } from '@/hooks'
import { formatSiteAddress } from '@/lib/format'
import { useAuthStore } from '@/stores/authStore'

const rowClass = 'flex min-h-11 w-full flex-wrap items-center justify-between gap-2 rounded-md px-2 py-2 text-left font-medium break-all text-fg-brand-strong underline hover:bg-recessed focus-visible:ring-2 md:min-h-9'

export function MaintenanceTargetsPage({ target }: { target: 'sites' | 'agents' }) {
  const { t } = useTranslation()
  const user = useAuthStore(s => s.user?.id)
  const canWrite = useAuthStore(s => s.user?.role === 'admin')
  const navigate = useNavigate()
  const [directoryNode, setDirectoryNode] = useState<{ id: string; name: string } | null>(null)
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
          to: '',
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
        {!list.data.rows.length && (query.search ? <EmptyState
          icon={<MagnifyingGlass />} title={t(target === 'sites' ? 'pages.sites.noResults' : 'pages.agents.noResults')}
          description={t(target === 'sites' ? 'pages.sites.noResultsDescription' : 'pages.agents.noResultsDescription', { query: query.search })}
          action={<Button onClick={() => { setSearch(''); setPage(1) }}>{t('nav.clearTargetSearch')}</Button>}
        /> : <EmptyState icon={target === 'sites' ? <Globe /> : <Desktop />}
          title={t(target === 'sites' ? (canWrite ? 'pages.sites.emptyTitle' : 'nav.emptySiteScope') : 'pages.agents.empty')}
          description={t(target === 'sites' ? (canWrite ? 'pages.sites.emptyDescription' : 'nav.chooseProtectionSite') : 'pages.agents.emptyDescription')}
          action={canWrite && <Button variant="primary" onClick={() => navigate(target === 'sites' ? '/sites?new=1' : '/agents')}>
            {t(target === 'sites' ? 'pages.sites.addSite' : 'nav.agents')}
          </Button>}
        />)}
        <ul className="divide-y divide-line">{list.data.rows.map(row =>
          <li key={row.id} className="text-sm">
            {target === 'agents' ? <button type="button" className={rowClass} onClick={() => setDirectoryNode(row)}>
              <span>{row.name}</span>{row.detail !== row.name && <span className="text-fg-subtle">{row.detail}</span>}
            </button> : row.to ? <Link className={rowClass} to={row.to}>
              <span>{row.name}</span>{row.detail !== row.name && <span className="text-fg-subtle">{row.detail}</span>}
            </Link> : <div className="flex flex-wrap justify-between gap-2 py-2">
              <span className="break-all">{row.name}</span><span className="text-fg-subtle">{t('nav.protectionUnavailable')}</span>
            </div>}
          </li>)}</ul>
        {(page > 1 || list.data.total > query.page_size) && <Pagination page={page} pageSize={query.page_size} total={list.data.total} onChange={setPage} />}
      </>}
    </CardBody></Card>
    {directoryNode && <StaticRootsDialog node={directoryNode.id} name={directoryNode.name} close={() => setDirectoryNode(null)} />}
  </div>
}
